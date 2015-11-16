{-# LANGUAGE ExistentialQuantification #-}
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

data SomeNetworkStack = forall lsock sock . HasBackend sock => MkNS (TorNetworkStack lsock sock)

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

recvLine :: TorNetworkStack ls s -> s -> IO L.ByteString
recvLine ns s = go []
 where
  go acc =
    do next <- recv ns s 1
       case S.uncons next of
         Nothing      -> return (L.pack (reverse acc))
         Just (10, _) -> return (L.pack (reverse acc))
         Just (f, _)  -> go (f:acc)

recvAll :: TorNetworkStack ls s -> s -> IO L.ByteString
recvAll ns s = go []
 where
  go acc =
    do next <- recv ns s 4096
       if S.null next
          then return (L.fromChunks (reverse acc))
          else go (next:acc)

toBackend :: TorNetworkStack ls s -> s -> Backend
toBackend ns s = Backend {
    backendFlush = flush ns s
  , backendClose = close ns s
  , backendRecv  = recv  ns s
  , backendSend  = write ns s . L.fromStrict
  }
