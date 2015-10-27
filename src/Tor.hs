{-# LANGUAGE ExistentialQuantification #-}
module Tor(
         -- * Setup and initialization
         Tor
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

import Control.Monad
import Data.ByteString(ByteString)
import Data.Maybe
import Data.Word
import Network.TLS
import Tor.NetworkStack hiding (connect)
import Tor.Options
import Tor.State.CircuitManager
import Tor.State.Credentials
import Tor.State.Directories
import Tor.State.LinkManager
import Tor.State.Routers

type HostName = String

-- |A handle to the current Tor system state.
data Tor = Tor {
       _torOptions        :: TorOptions
     , _torCircuitManager :: CircuitManager
     }

-- |Start up the underlying Tor system, given a network stack to operate in and
-- some setup options.
startTor :: HasBackend s => TorNetworkStack ls s -> TorOptions -> IO Tor
startTor ns o =
  do creds    <- newCredentials (torLog o)
     dirDB    <- newDirectoryDatabase ns (torLog o)
     routerDB <- newRouterDatabase ns dirDB (torLog o)
     lm       <- newLinkManager o ns routerDB creds
     cm       <- newCircuitManager o routerDB lm
     when (not isRelay && isExit) $
       do torLog o "WARNING: Requested exit without relay support: weird."
          torLog o "WARNING: Please check that this is really what you want."
     return (Tor o cm)
 where
  isRelay    = isJust (torRelayOptions o)
  isExit     = isJust (torExitOptions o)

-- -----------------------------------------------------------------------------

-- |Resolve the given host name, anonymously. This routine will create a new
-- circuit unless torMaxCircuits has been reached, at which point it will re-use
-- an existing circuit.
resolveName :: Tor -> HostName -> IO Int
resolveName = undefined

data ConnectionOptions = None

data TorSocket = TorSocket

connect :: Tor -> ConnectionOptions -> HostName -> Word16 -> IO TorSocket
connect = undefined TorSocket

writeBS :: TorSocket -> ByteString -> IO ()
writeBS = undefined

readBS :: TorSocket -> Int -> IO ByteString
readBS = undefined
