module Tor.NetworkStack(
         TorNetworkStack(..)
       , toIOSystem
       , recvAll
       , recvLine
       )
 where

import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Word
import TLS.Context

data TorNetworkStack lsock sock = TorNetworkStack {
       connect :: String -> Word16     -> IO (Maybe sock)
     , listen  :: Word16               -> IO lsock
     , accept  :: lsock                -> IO (sock, String)
     , recv    :: sock   -> Int        -> IO ByteString
     , write   :: sock   -> ByteString -> IO ()
     , flush   :: sock                 -> IO ()
     , close   :: sock                 -> IO ()
     , lclose  :: lsock                -> IO ()
     }

recvLine :: TorNetworkStack ls s -> s -> IO ByteString
recvLine ns s =
  do next <- recv ns s 1
     case BS.uncons next of
       Nothing      -> return BS.empty
       Just (10, _) -> return next
       Just (f, _)  -> BS.cons f `fmap` recvLine ns s

recvAll :: TorNetworkStack ls s -> s -> IO ByteString
recvAll ns s =
  do next <- recv ns s 4096
     if BS.null next
        then return next
        else (next `BS.append`) `fmap` recvAll ns s

toIOSystem :: TorNetworkStack ls s -> s -> IOSystem
toIOSystem ns s = IOSystem {
    ioRead  = recv ns s
  , ioWrite = write ns s
  , ioFlush = flush ns s
  }
