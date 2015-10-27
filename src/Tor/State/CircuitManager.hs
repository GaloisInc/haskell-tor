module Tor.State.CircuitManager(
         CircuitManager
       , newCircuitManager
       , openCircuit
       , closeCircuit
       )
 where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Exception
import Control.Monad
import Crypto.Random
import Data.Word
import Network.TLS(HasBackend)
import System.Mem.Weak
import Tor.Circuit
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.Link
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.LinkManager
import Tor.State.Routers

data CircuitManager = NoCircuitManager
                    | CircuitManager {
                        cmCircuitLength :: Int
                      , cmRouterDB      :: RouterDB
                      , cmLog           :: String -> IO ()
                      , cmRNG           :: MVar TorRNG
                      , cmOpenCircuits  :: MVar [CircuitEntry]
                      , _cmOpenLinks     :: MVar [TorLink]
                      }

data CircuitEntry = Pending {
                      ceExitNode        :: RouterDesc
                    , _cePendingEntrance :: Async TorEntrance
                    }
                  | Entry {
                      ceExitNode        :: RouterDesc
                    , _ceWeakEntrance    :: Weak TorEntrance
                    }

newCircuitManager :: HasBackend s =>
                     TorOptions -> RouterDB -> LinkManager ls s ->
                     IO CircuitManager
newCircuitManager opts rdb _lm =
  case torEntranceOptions opts of
    Nothing      -> return NoCircuitManager
    Just entOpts ->
      do let circLen = torInternalCircuitLength entOpts
         rngMV  <- newMVar =<< drgNew
         circMV <- newMVar []
         linkMV <- newMVar []
         return (CircuitManager circLen rdb (torLog opts) rngMV circMV linkMV)

-- |Open a circuit to an exit node that allows connections to the given
-- host and port.
openCircuit :: CircuitManager -> String -> Word16 -> IO TorEntrance
openCircuit NoCircuitManager _ _ = fail "This node doesn't support entrance."
openCircuit cm dest port =
  join $ modifyMVar (cmOpenCircuits cm) $ \ circs ->
    case findApplicable circs of
      Nothing ->
        do exitNode <- modifyMVar (cmRNG cm) $ \ rng ->
                         getRouter (cmRouterDB cm) restricts rng
           pendRes <- async (buildNewCircuit cm exitNode (cmCircuitLength cm))
           return (snoc circs (Pending exitNode pendRes),
                   waitAndUpdate exitNode pendRes)
      Just (pend@(Pending _ entrance), rest) ->
        return (snoc rest pend, wait entrance)
      Just (ent@(Entry _ wkEnt), rest) ->
        do ment <- deRefWeak wkEnt
           case ment of
             Nothing ->
               return (rest, openCircuit cm dest port)
             Just res ->
               return (snoc rest ent, return res)
 where
  restricts = [ExitNodeAllowing (IP4 dest) port]
  --
  findApplicable ls = loop ls []
   where
    loop [] _ = Nothing
    loop (x : rest) acc
      | ceExitNode x `meetsRestrictions` restricts = Just (x, rest ++ acc)
      | otherwise                                  = loop rest (snoc acc x)
  --
  waitAndUpdate :: RouterDesc -> Async TorEntrance -> IO TorEntrance
  waitAndUpdate exitNode pendRes =
    do eres <- waitCatch pendRes
       case eres of
         Left err ->
           do modifyMVar_ (cmOpenCircuits cm)
                (return . removeEntry exitNode)
              throwIO err
         Right res ->
           do weak <- mkWeakPtr res (Just (destroyCircuit res RequestedDestroy))
              let newent = Entry exitNode weak
              modifyMVar_ (cmOpenCircuits cm)
                (return . replaceEntry exitNode newent)
              return res
  --
  removeEntry _        [] = []
  removeEntry exitNode (x : rest)
    | exitNode == ceExitNode x = removeEntry exitNode rest
    | otherwise                = x : removeEntry exitNode rest
  --
  replaceEntry _        _   [] = []
  replaceEntry exitNode new (x : rest)
    | exitNode == ceExitNode x = new : replaceEntry exitNode new rest
    | otherwise                = x   : replaceEntry exitNode new rest

closeCircuit :: CircuitManager -> TorEntrance -> IO ()
closeCircuit = undefined

buildNewCircuit :: CircuitManager -> RouterDesc -> Int -> IO TorEntrance
buildNewCircuit cm exitNode _len =
  do entrance <- modifyMVar (cmRNG cm)
                    (getRouter (cmRouterDB cm) [NotRouter exitNode])
     circ     <- createCircuit (cmRNG cm) (cmLog cm) undefined entrance 4
     undefined circ -- FIXME

snoc :: [a] -> a -> [a]
snoc []       x = [x]
snoc (x:rest) y = x : snoc rest y

