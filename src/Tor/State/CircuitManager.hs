module Tor.State.CircuitManager(
         startCircuitManager
       , openCircuit
       , closeCircuit
       )
 where

import Control.Concurrent
import Control.Monad
import Data.Array.IO
import System.Mem.Weak
import Tor.Circuit
import Tor.Options

data CircuitManager = NoCircuitManager
                    | CircuitManager {
                        cmCircuitLength :: Int
                      , cmNextCircuit   :: MVar Int
                      , cmCircuits      :: IOArray Int (MVar CircuitEntry)
                      }

data CircuitEntry = NoCircuit | Entry (Weak TorEntrance)

startCircuitManager :: TorOptions -> IO CircuitManager
startCircuitManager opts =
  case torEntranceOptions opts of
    Nothing      -> return NoCircuitManager
    Just entOpts ->
      do let circLen = torInternalCircuitLength entOpts
             numEnts = torMaxCircuits entOpts - 1
         nos   <- replicateM numEnts (newMVar NoCircuit)
         arr   <- newListArray (0, torMaxCircuits entOpts - 1) nos
         idxMV <- newMVar 1
         return (CircuitManager circLen idxMV arr)


openCircuit :: CircuitManager -> IO TorEntrance
openCircuit cm =
  do idx   <- advanceIndex (cmNextCircuit cm)
     entMV <- readArray (cmCircuits cm) idx
     modifyMVar entMV $ \ ent ->
       case ent of
         NoCircuit  -> buildNewCircuit cm
         Entry entW ->
           do ment <- deRefWeak entW
              case ment of
                Just x  -> return (ent, x)
                Nothing -> buildNewCircuit cm

closeCircuit :: CircuitManager -> TorEntrance -> IO ()
closeCircuit = undefined

buildNewCircuit :: CircuitManager -> IO (CircuitEntry, TorEntrance)
buildNewCircuit = undefined

advanceIndex :: Enum a => MVar a -> IO a
advanceIndex idxMV = modifyMVar idxMV (\ x -> return (succ x, x))



