{-# LANGUAGE ExistentialQuantification #-}
-- |Defines the network API required for a Tor implementation to run.
module Tor.NetworkStack(
         TorNetworkStack(..)
       , SomeNetworkStack(..)
       , toBackend
       , recvAll
       , recvLine
       )
 where

import qualified Data.ByteString      as S
import qualified Data.ByteString.Lazy as L
import Data.Word
import Network.TLS
import Tor.DataFormat.TorAddress

-- |A network stack, but with the type variables hidden.
data SomeNetworkStack = forall lsock sock . HasBackend sock =>
       MkNS (TorNetworkStack lsock sock)

-- |The type of a Tor-compatible network stack. The first type variable is the
-- type of a listener socket, the second the type of a standard connection
-- socket. 
data TorNetworkStack lsock sock = TorNetworkStack {
       connect    :: String -> Word16       -> IO (Maybe sock)
       -- |Lookup the given hostname and return any IP6 (Left) or IP4 (Right)
       -- addresses associated with it.
     , getAddress :: String                 -> IO [TorAddress]
     , listen     :: Word16                 -> IO lsock
     , accept     :: lsock                  -> IO (sock, TorAddress)
     , recv       :: sock   -> Int          -> IO S.ByteString
     , write      :: sock   -> L.ByteString -> IO ()
     , flush      :: sock                   -> IO ()
     , close      :: sock                   -> IO ()
     , lclose     :: lsock                  -> IO ()
     }

-- |Receive a line of ASCII text from a socket.
recvLine :: TorNetworkStack ls s -> s -> IO L.ByteString
recvLine ns s = go []
 where
  go acc =
    do next <- recv ns s 1
       case S.uncons next of
         Nothing      -> return (L.pack (reverse acc))
         Just (10, _) -> return (L.pack (reverse acc))
         Just (f, _)  -> go (f:acc)

-- |Receive all the input from the socket as a lazy ByteString; this may cause
-- the system to block upon some ByteString operations to fetch more data.
recvAll :: TorNetworkStack ls s -> s -> IO L.ByteString
recvAll ns s = go []
 where
  go acc =
    do next <- recv ns s 4096
       if S.null next
          then return (L.fromChunks (reverse acc))
          else go (next:acc)

-- |Convert a Tor-compatible network stack to a TLS-compatible Backend
-- structure.
toBackend :: TorNetworkStack ls s -> s -> Backend
toBackend ns s = Backend {
    backendFlush = flush ns s
  , backendClose = close ns s
  , backendRecv  = recv  ns s
  , backendSend  = write ns s . L.fromStrict
  }
