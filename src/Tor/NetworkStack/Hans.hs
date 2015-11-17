-- |The way to integrate Tor with Hans.
module Tor.NetworkStack.Hans(hansNetworkStack) where

import Data.ByteString(ByteString)
import qualified Data.ByteString.Lazy as L
import Data.Word
import Hans.Address.IP4
import Hans.NetworkStack
import Tor.DataFormat.TorAddress(TorAddress)
import qualified Tor.DataFormat.TorAddress as TorAddr
import Tor.NetworkStack(TorNetworkStack(TorNetworkStack))
import qualified Tor.NetworkStack

-- |Create a Tor-compatible network stack from the given Hans network stack.
hansNetworkStack :: (HasTcp stack, HasDns stack) =>
                    stack ->
                    TorNetworkStack Socket Socket
hansNetworkStack ns = TorNetworkStack {
    Tor.NetworkStack.connect    = systemConnect ns
  , Tor.NetworkStack.getAddress = systemLookup ns
  , Tor.NetworkStack.listen     = systemListen ns
  , Tor.NetworkStack.accept     = systemAccept
  , Tor.NetworkStack.recv       = systemRead
  , Tor.NetworkStack.write      = systemWrite
  , Tor.NetworkStack.flush      = const (return ())
  , Tor.NetworkStack.close      = close
  , Tor.NetworkStack.lclose     = close
  }

systemConnect :: (HasTcp stack, HasDns stack) =>
                 stack -> String -> Word16 ->
                 IO (Maybe Socket)
systemConnect stack addr port =
  do mipAddr <- getAddr (reads addr) addr
     case mipAddr of
       Nothing     -> return Nothing
       Just ipAddr -> Just `fmap` connect stack ipAddr port' Nothing
 where
  port' = fromIntegral port
  --
  getAddr [(x, _)] _ = return (Just x)
  getAddr _        x =
    do hentry <- getHostByName stack x
       case hostAddresses hentry of
         []    -> return Nothing
         (i:_) -> return (Just i)

systemLookup :: HasDns stack => stack -> String -> IO [TorAddress]
systemLookup stack name =
  do host <- getHostByName stack name
     return (map (TorAddr.IP4 . show) (hostAddresses host))

systemListen :: (HasTcp stack) =>
                stack -> Word16 ->
                IO Socket
systemListen stack port = listen stack broadcastIP4 (fromIntegral port)

systemAccept :: Socket -> IO (Socket, TorAddress)
systemAccept lsock =
  do sock <- accept lsock
     return (sock, TorAddr.IP4 (show (sockRemoteHost sock)))

systemRead :: Socket -> Int -> IO ByteString
systemRead sock amt = L.toStrict `fmap` loop (fromIntegral amt)
 where loop x | x <= 0    = return L.empty
              | otherwise =
         do bstr <- recvBytes sock x
            if L.null bstr
               then return L.empty
               else (bstr `L.append`) `fmap` loop (x - L.length bstr)

systemWrite :: Socket -> L.ByteString -> IO ()
systemWrite sock bstr =
  do amt <- sendBytes sock bstr
     if (amt == 0) || (amt == L.length bstr)
        then return ()
        else systemWrite sock (L.drop amt bstr)

