module Tor.State.CircuitManager(
         CircuitManager
       , newCircuitManager
       , openCircuit
       , closeCircuit
       )
 where

import Control.Concurrent
import Control.Concurrent.Async(Async,async,wait,waitCatch)
import Control.Exception
import Control.Monad
import Crypto.Random
import Network.TLS(HasBackend)
import System.Mem.Weak
import Tor.Circuit
import Tor.DataFormat.TorCell
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.LinkManager
import Tor.State.Routers

data HasBackend s => CircuitManager ls s
       = NoCircuitManager
       | CircuitManager {
           cmCircuitLength :: Int
         , cmRouterDB      :: RouterDB
         , cmLog           :: String -> IO ()
         , cmLinkManager   :: LinkManager ls s
         , cmRNG           :: MVar TorRNG
         , cmOpenCircuits  :: MVar [CircuitEntry]
         }

data CircuitEntry = Pending {
                      ceExitNode        :: RouterDesc
                    , _cePendingEntrance :: Async TorCircuit
                    }
                  | Entry {
                      ceExitNode        :: RouterDesc
                    , _ceWeakEntrance    :: Weak TorCircuit
                    }

newCircuitManager :: HasBackend s =>
                     TorOptions -> RouterDB -> LinkManager ls s ->
                     IO (CircuitManager ls s)
newCircuitManager opts rdb lm =
  case torEntranceOptions opts of
    Nothing      -> return NoCircuitManager
    Just entOpts ->
      do let circLen = torInternalCircuitLength entOpts
         rngMV  <- newMVar =<< drgNew
         circMV <- newMVar []
         let cm = CircuitManager circLen rdb (torLog opts) lm rngMV circMV
         setIncomingLinkHandler lm $ \ link ->
           handle logException $
             do _circuit <- acceptCircuit link
                torLog opts ("HANDLE INCOMING CIRCUIT FIXME")
         return cm
 where
  logException e = torLog opts ("Exception creating incoming circuit: " ++
                                show (e :: SomeException))

-- |Open a circuit to an exit node that allows connections to the given
-- host and port.
openCircuit :: HasBackend s =>
               CircuitManager ls s -> [RouterRestriction] ->
               IO TorCircuit
openCircuit NoCircuitManager _ = fail "This node doesn't support entrance."
openCircuit cm restricts =
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
               return (rest, openCircuit cm restricts)
             Just res ->
               return (snoc rest ent, return res)
 where
  findApplicable ls = loop ls []
   where
    loop [] _ = Nothing
    loop (x : rest) acc
      | ceExitNode x `meetsRestrictions` restricts = Just (x, rest ++ acc)
      | otherwise                                  = loop rest (snoc acc x)
  --
  waitAndUpdate :: RouterDesc -> Async TorCircuit -> IO TorCircuit
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

closeCircuit :: HasBackend s => CircuitManager ls s -> TorCircuit -> IO ()
closeCircuit = error "closeCircuit"

-- This is the code that actually builds a circuit, given an appropriate
-- final node.
--
-- FIXME: Make sure that we don't use two routers within the same family.
-- FIXME: Make sure that we don't use two routers within the same /16 subnet.
-- FIXME: Use the path selection weighting criteria in path-spec.txt
--
buildNewCircuit :: HasBackend s =>
                   CircuitManager ls s -> RouterDesc -> Int ->
                   IO TorCircuit
buildNewCircuit cm exitNode len =
  do let notExit = [NotRouter exitNode]
     (link, desc, circId) <- newLinkCircuit (cmLinkManager cm) notExit
     cmLog cm ("Built initial link to " ++ show (routerIPv4Address desc) ++
               " with circuit ID " ++ show circId)
     circ <- createCircuit (cmRNG cm) (cmLog cm) link desc circId
     loop circ (NotRouter desc : notExit) len
 where
  loop circ _         0 =
    do cmLog cm ("Extending circuit to exit node " ++
                 show (routerIPv4Address exitNode))
       extendCircuit circ exitNode
       return circ
  loop circ restricts x =
    do next <- modifyMVar (cmRNG cm) (getRouter (cmRouterDB cm) restricts)
       cmLog cm ("Extending circuit to " ++ show (routerIPv4Address next))
       extendCircuit circ next
       loop circ (NotRouter next : restricts) (x - 1)

snoc :: [a] -> a -> [a]
snoc []       x = [x]
snoc (x:rest) y = x : snoc rest y

