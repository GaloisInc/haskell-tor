{-# LANGUAGE ExistentialQuantification #-}
module Tor(
         -- * Setup and initialization
         TorNetworkStack(..)
       , Tor
       , startTor
         -- * Options
       , module Tor.Options
         -- * Functions for Tor entrance nodes
       , ConnectionOptions(..)
       , resolveName
       , connect
       , close
       , writeBS
       , readBS
       )
 where

import Control.Concurrent
import Control.Monad
import Data.ByteString(ByteString)
import Data.Maybe
import Data.Word
import Network.TLS
import Tor.Link
import Tor.NetworkStack hiding (connect)
import Tor.Options
import Tor.State

type HostName = String

-- |A handle to the current Tor system state.
data Tor = forall ls s . Tor {
       torState   :: TorState ls s
     , torOptions :: TorOptions
     }

-- |Start up the underlying Tor system, given a network stack to operate in and
-- some setup options.
startTor :: HasBackend s => TorNetworkStack ls s -> TorOptions -> IO Tor
startTor ns opts =
  do torst <- initializeTorState ns opts
     when (isRelay || isExit) $
       do lsock <- listen ns orPort
          logm ("Waiting for Tor connections on port " ++ show orPort)
          forkIO_ $ forever $ do (sock, addr) <- accept ns lsock
                                 forkIO_ (acceptIncomingLink torst sock addr)
     when (not isRelay && isExit) $
       do logm "WARNING: Requested exit without relay support: this is weird."
          logm "WARNING: Please check that this is really what you want."
     return (Tor torst opts)
 where
  isRelay = isJust (torRelayOptions opts)
  isExit  = isJust (torExitOptions opts)
  orPort  = maybe 9374 torOnionPort (torRelayOptions opts)
  flags   = undefined
  logm    = torLog opts

-- -----------------------------------------------------------------------------

-- |Resolve the given host name, anonymously. This routine will create a new
-- circuit unless torMaxCircuits has been reached, at which point it will re-use
-- an existing circuit.
resolveName :: Tor -> HostName -> IO Int
resolveName = undefined

data ConnectionOptions = None

data TorSocket = TorSocket

connect :: Tor -> ConnectionOptions -> HostName -> Word16 -> IO TorSocket
connect = undefined

writeBS :: TorSocket -> ByteString -> IO ()
writeBS = undefined

readBS :: TorSocket -> Int -> IO ByteString
readBS = undefined

-- -----------------------------------------------------------------------------

forkIO_ :: IO () -> IO ()
forkIO_ m = forkIO m >> return ()
