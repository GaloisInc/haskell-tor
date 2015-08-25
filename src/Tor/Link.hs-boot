module Tor.Link(
         TorLink
       , initializeClientTorLink
       , acceptIncomingLink
       --
       , newRandomCircuit
       , modifyCircuitHandler
       , endCircuit
       , writeCell
       )
 where

import Control.Concurrent.STM
import Crypto.Random
import Data.Map.Strict(Map)
import Data.Word
import Network.TLS
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.RouterDesc
import Tor.State

type CircuitHandler = TorCell -> IO ()

data TorLink = TorLink {
       linkContext           :: Context
     , linkInitiatedRemotely :: Bool
     , linkHandlerTable      :: TVar (Map Word32 CircuitHandler)
     }

initializeClientTorLink :: HasBackend s =>
                           TorState ls s -> RouterDesc ->
                           IO (Either String TorLink)

acceptIncomingLink :: HasBackend s =>
                      TorState ls s -> s -> TorAddress ->
                      IO ()

newRandomCircuit :: DRG g =>
                    TorLink -> CircuitHandler -> g ->
                    STM (Word32, g)

modifyCircuitHandler :: TorLink -> Word32 -> CircuitHandler -> IO ()

endCircuit :: TorLink -> Word32 -> IO ()

writeCell :: TorLink -> TorCell -> IO ()


