{-# LANGUAGE ExistentialQuantification #-}
module Tor(
         -- * Setup and initialization
         Tor
       , startTor
         -- * Options
       , module Tor.Options
         -- * Functions for Tor entrance nodes
       , TorAddress(..)
       , RelayEndReason(..)
       , torResolveName
       , TorSocket
       , torConnect
       , torClose
       , torWrite
       , torRead
       )
 where

import Control.Exception
import Control.Monad
import Data.Maybe
import Data.Word
import Network.TLS
import System.Timeout
import Tor.Circuit
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.NetworkStack hiding (connect)
import Tor.Options
import Tor.State.CircuitManager
import Tor.State.Credentials
import Tor.State.Directories
import Tor.State.LinkManager
import Tor.State.Routers

type HostName = String

-- |A handle to the current Tor system state.
data Tor = forall ls s . HasBackend s => Tor (CircuitManager ls s)

-- |Start up the underlying Tor system, given a network stack to operate in and
-- some setup options.
startTor :: HasBackend s => TorNetworkStack ls s -> TorOptions -> IO Tor
startTor ns o =
  do creds    <- newCredentials o
     dirDB    <- newDirectoryDatabase ns (torLog o)
     routerDB <- newRouterDatabase ns dirDB (torLog o)
     lm       <- newLinkManager o ns routerDB creds
     cm       <- newCircuitManager o ns creds routerDB lm
     when (not isRelay && isExit) $
       do torLog o "WARNING: Requested exit without relay support: weird."
          torLog o "WARNING: Please check that this is really what you want."
     let res = Tor cm
     when (isRelay || isExit) $
       handle (checkPublicFail o) $
         do _      <- torResolveName res "google.com" -- not important
            addrs  <- getAddresses creds
            torLog o ("I believe I have the following addrs: " ++ show addrs)
            fin <- timeout (15 * 1000000) $ tryConnect res orPort addrs
            unless (isJust fin) $ fail "Timeout connecting to myself."
            torLog o ("At least one of which is routable. Starting relay.")
            (_, PrivKeyRSA pkey) <- getSigningKey creds
            desc <- getRouterDesc creds
            sendRouterDescription ns (torLog o) dirDB desc pkey
     return (Tor cm)
 where
  isRelay    = isJust (torRelayOptions o)
  isExit     = isJust (torExitOptions o)
  orPort     = maybe 9374 torOnionPort (torRelayOptions o)

tryConnect :: Tor -> Word16 -> [TorAddress] -> IO ()
tryConnect _   _ []       = fail "Could not connect to any addresses."
tryConnect tor p (x:rest) =
  handle failRecurse $
    do con <- torConnect tor x p
       torClose con ReasonDone
 where
  failRecurse :: SomeException -> IO ()
  failRecurse _ = tryConnect tor p rest

checkPublicFail :: TorOptions -> SomeException -> IO ()
checkPublicFail o _ =
  torLog o ("Failed to create connection to myself. No relay/exit support.")

-- -----------------------------------------------------------------------------

-- |Resolve the given host name, anonymously. This routine will create a new
-- circuit unless torMaxCircuits has been reached, at which point it will re-use
-- an existing circuit.
torResolveName :: Tor -> HostName -> IO [(TorAddress, Word32)]
torResolveName (Tor cm) name =
  do circ <- openCircuit cm [ExitNode]
     resolveName circ name

torConnect :: Tor -> TorAddress -> Word16 -> IO TorSocket
torConnect (Tor cm) addr port =
  do circ <- openCircuit cm [ExitNodeAllowing addr port]
     connectToHost circ addr port



