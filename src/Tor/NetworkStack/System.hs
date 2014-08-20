module Tor.NetworkStack.System(systemNetworkStack) where

import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Word
import Network.BSD
import Network.Socket as Sys hiding (recv)
import Network.Socket.ByteString.Lazy(sendAll)
import qualified Network.Socket.ByteString.Lazy as Sys
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
systemListen port =
  do sock <- socket AF_INET Stream defaultProtocol
     bind sock (SockAddrInet (PortNum port) iNADDR_ANY)
     Sys.listen sock 3
     return sock

systemAccept :: Socket -> IO (Socket, String)
systemAccept lsock =
  do (res, addr) <- Sys.accept lsock
     return (res, show addr)

systemRead :: Socket -> Int -> IO ByteString
systemRead _    0   = return BS.empty
systemRead sock amt =
  do start <- Sys.recv sock (fromIntegral amt)
     let left = fromIntegral (amt - fromIntegral (BS.length start))
     if BS.null start
        then return BS.empty
        else (start `BS.append`) `fmap` systemRead sock left

