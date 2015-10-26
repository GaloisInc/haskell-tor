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
import Crypto.Random
import Data.Word
import System.Mem.Weak
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.Link
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
                      , cmOpenLinks     :: MVar [TorLink]
                      }

data CircuitEntry = Pending {
                      ceExitNode        :: RouterDesc
                    , cePendingEntrance :: Async TorEntrance
                    }
                  | Entry {
                      ceExitNode        :: RouterDesc
                    , ceWeakEntrance    :: Weak TorEntrance
                    }


startCircuitManager :: TorOptions -> RouterDB -> LinkManager -> IO CircuitManager
startCircuitManager opts rdb lm =
  case torEntranceOptions opts of
    Nothing      -> return NoCircuitManager
    Just entOpts ->
      do let circLen = torInternalCircuitLength entOpts
         rngMV  <- newMVar =<< drgNew
         circMV <- newMVar []
         linkMV <- newMVar []
         setIncomingLinkHandler lm $ \ link ->
           do modifyMVar_ linkMV (return . (link:))
              runIncomingCircuit link
         return (CircuitManager circLen rdb rngMV circMV linkMV)

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
buildNewCircuit cm exitNode len =
  do entrance <- getRouter (cmRouterDB cm) [NotRounter exitNode]
     circ     <- createCircuit undefined entrance

snoc :: [a] -> a -> [a]
snoc []       x = [x]
snoc (x:rest) y = x : snoc rest y

