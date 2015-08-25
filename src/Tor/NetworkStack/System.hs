module Tor.NetworkStack.System(systemNetworkStack) where

import Data.Binary.Put
import Data.ByteString(ByteString)
import Data.ByteString.Lazy(toStrict)
import qualified Data.ByteString as BS
import Data.Word
import Network(listenOn, PortID(..))
import Network.BSD
import Network.Socket as Sys hiding (recv)
import Network.Socket.ByteString.Lazy(sendAll)
import qualified Network.Socket.ByteString as Sys
import Tor.DataFormat.TorAddress
import Tor.NetworkStack

systemNetworkStack :: TorNetworkStack Socket Socket
systemNetworkStack = TorNetworkStack {
    Tor.NetworkStack.connect = systemConnect
  , Tor.NetworkStack.listen  = systemListen
  , Tor.NetworkStack.accept  = systemAccept
  , Tor.NetworkStack.recv    = systemRead
  , Tor.NetworkStack.write   = sendAll
  , Tor.NetworkStack.flush   = const (return ())
  , Tor.NetworkStack.close   = Sys.close
  , Tor.NetworkStack.lclose  = Sys.close
  }

systemConnect :: String -> Word16 -> IO (Maybe Socket)
systemConnect addrStr port =
  do let ainfo = defaultHints { addrFamily = AF_INET, addrSocketType = Stream }
         hname = addrStr
         sname = show port
     addrinfos <- getAddrInfo (Just ainfo) (Just hname) (Just sname)
     case addrinfos of
       []    -> return Nothing
       (x:_) ->
         do sock <- socket AF_INET Stream defaultProtocol
            Sys.connect sock (addrAddress x)
            return (Just sock)

systemListen :: Word16 -> IO Socket
systemListen port = listenOn (PortNumber (fromIntegral port))

systemAccept :: Socket -> IO (Socket, TorAddress)
systemAccept lsock =
  do (res, addr) <- Sys.accept lsock
     case addr of
       SockAddrInet _ addr' ->
         let bstr = toStrict (runPut (putWord32be addr'))
         in return (res, IP4 (ip4ToString bstr))
       SockAddrInet6 _ _ (a,b,c,d) _ ->
         let bstr = toStrict (runPut (mapM_ putWord32be [a,b,c,d]))
         in return (res, IP6 (ip6ToString bstr))
       SockAddrUnix  _          -> fail "Unix socket? BAD."
       SockAddrCan   _          -> fail "CAN socket? BAD."

systemRead :: Socket -> Int -> IO ByteString
systemRead _    0   = return BS.empty
systemRead sock amt =
  do start <- Sys.recv sock (fromIntegral amt)
     let left = fromIntegral (amt - fromIntegral (BS.length start))
     if BS.null start
        then return BS.empty
        else (start `BS.append`) `fmap` systemRead sock left

