module Tor.State.CircuitManager(
         startCircuitManager
       , openCircuit
       , closeCircuit
       )
 where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Exception
import Control.Monad
import Data.Word
import System.Mem.Weak
import Tor.Circuit
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Routers

data CircuitManager = NoCircuitManager
                    | CircuitManager {
                        cmCircuitLength :: Int
                      , cmRouterDB      :: RouterDB
                      , cmRNG           :: MVar TorRNG
                      , cmOpenCircuits  :: MVar [CircuitEntry]
                      }

data CircuitEntry = Pending RouterDesc (Async TorEntrance)
                  | Entry   RouterDesc (Weak TorEntrance)


startCircuitManager :: TorOptions -> IO CircuitManager
startCircuitManager opts =
  case torEntranceOptions opts of
    Nothing      -> return NoCircuitManager
    Just entOpts ->
      do let circLen = torInternalCircuitLength entOpts
         circMV <- newMVar []
         return (CircuitManager circLen circMV)


-- |Open a circuit to an exit node that allows connections to the given
-- host and port.
openCircuit :: CircuitManager -> String -> Word16 -> IO TorEntrance
openCircuit NoCircuitManager _ _ = fail "This node doesn't support entrance."
openCircuit cm dest port =
  join $ modifyMVar (cmOpenCircuits cm) $ \ circs ->
    case findApplicable circs of
      Nothing ->
        do exitNode <- modifyMVar (cmRNG cm) $ \ rng ->
                         getRouter (cmRouterDB cm) restricts (cmRNG cm)
           pendRes <- async (buildNewCircuit exitNode (cmCircuitLength cm))
           return (snoc circs (Pending exitNode pendRes),
                   waitAndUpdate exitNode pendRes)
      Just (pend@(Pending _ entrance), rest) ->
        return (snoc rest pend, wait entrance)
      Just (ent@(Entry _ wkEnt), rest) ->
        do ment <- deRefWeak wkEnt
           case ment of
             Nothing ->
               return (rest, openCircuit cm dest port)
             Just ent ->
               return (snoc rest ent, return ent)
 where
  restricts = [ExitNodeAllowing (IP4 dest) port]
  --
  findApplicable ls = loop ls []
   where
    loop [] _ = Nothing
    loop (x@(Pending en _) : rest) acc
      | en `meetsRestrictions` restricts = Just (x, rest ++ acc)
      | otherwise                        = findApplicable rest (snoc acc x)
    loop (x@(Entry en _) : rest) acc
      | en `meetsRestrictions` restricts = Just (x, rest ++ acc)
      | otherwise                        = findApplicable rest (snoc acc x)
  --
  waitAndUpdate exitNode pendRes =
    do eres <- waitCatch pendRes
       case eres of
         Left err ->
           do modifyMVar_ (cmOpenCircuits cm) (removeEntry exitNode)
              throwIO err
         Right res ->
           do res <- mkWeakPtr res (Just (destroyCircuit res RequestedDestroy))
              let newent = Entry exitNode res
              modifyMVar_ (cmOpenCircuits cm) (replaceEntry exitNode newent)
              return res
  --
  removeEntry _        [] = []
  removeEntry exitNode (Pending en _ : rest)
    | exitNode == en = removeEntry exitNode rest
  removeEntry exitNode (Entry en _   : rest)
    | exitNode == en = removeEntry exitNode rest
  removeEntry exitNode (x            : rest)
                     = x : removeEntry exitNode rest
  --
  replaceEntry _        _   [] = []
  replaceEntry exitNode new (Pending en _ : rest)
    | exitNode == en = new : replaceEntry exitNode new rest
  replaceEntry exitNode new (Entry   en _ : rest)
    | exitNode == en = new : replaceEntry exitNode new rest
  replaceEntry exitNode new (x            : rest)
                     = x   : replaceEntry exitNode new rest

closeCircuit :: CircuitManager -> TorEntrance -> IO ()
closeCircuit = undefined

buildNewCircuit :: CircuitManager -> IO TorEntrance
buildNewCircuit = undefined

advanceIndex :: Enum a => MVar a -> IO a
advanceIndex idxMV = modifyMVar idxMV (\ x -> return (succ x, x))

snoc :: [a] -> a -> [a]
snoc []       x = [x]
snoc (x:rest) y = x : snoc rest y

