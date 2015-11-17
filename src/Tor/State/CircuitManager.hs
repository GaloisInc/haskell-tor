-- |This module provides a high-level interface for building, closing, and
-- managing open circuits within the Tor network.
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
import Tor.Link
import Tor.NetworkStack
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Credentials
import Tor.State.LinkManager
import Tor.State.Routers

-- |A handle for the circuit manager component, to be passed amongst functions
-- in this module.
data HasBackend s => CircuitManager ls s
       = NoCircuitManager
       | CircuitManager {
           cmCircuitLength :: Int
         , cmRouterDB      :: RouterDB
         , cmOptions       :: TorOptions
         , cmLinkManager   :: LinkManager ls s
         , cmRNG           :: MVar TorRNG
         , cmOpenCircuits  :: MVar [CircuitEntry s]
         }

data CircuitEntry s = Pending {
                        ceExitNode         :: RouterDesc
                      , _cePendingEntrance :: Async OriginatedCircuit
                      }
                    | Entry {
                        ceExitNode         :: RouterDesc
                      , _ceWeakEntrance    :: Weak OriginatedCircuit
                      }
                    | Transverse {
                        _ceIncomingLink    :: TorLink
                      , _ceCircuit         :: Weak (TransverseCircuit s)
                      }

-- |Create a new circuit manager given the previously-initialized components.
-- Using a circuit manager will allow you to more easily reuse circuits across
-- multiple connections, decreasing the overhead of using Tor. In additionally,
-- eventually you will be able to track and gather statistics on circuit history
-- over time by using this component.
newCircuitManager :: HasBackend s =>
                     TorOptions -> TorNetworkStack ls s ->
                     Credentials -> RouterDB -> LinkManager ls s ->
                     IO (CircuitManager ls s)
newCircuitManager opts ns creds rdb lm =
  case torEntranceOptions opts of
    Nothing      -> return NoCircuitManager
    Just entOpts ->
      do let circLen = torInternalCircuitLength entOpts
         rngMV  <- newMVar =<< drgNew
         circMV <- newMVar []
         let cm = CircuitManager circLen rdb opts lm rngMV circMV
         setIncomingLinkHandler lm $ \ link ->
           handle logException $
             do me <- getRouterDesc creds
                mcircuit <- acceptCircuit ns opts me creds rdb link rngMV
                case mcircuit of
                  Nothing ->
                    torLog opts ("Failed to build transverse circuit.")
                  Just circuit ->
                    do wkCircuit <- mkWeakPtr circuit Nothing
                       let circ = Transverse link wkCircuit
                       modifyMVar_ circMV $ \ circs -> return (circ : circs)
         return cm
 where
  logException e = torLog opts ("Exception creating incoming circuit: " ++
                                show (e :: SomeException))

-- |Open a circuit to an exit node that allows connections according to the
-- given restrictions.
openCircuit :: HasBackend s =>
               CircuitManager ls s -> [RouterRestriction] ->
               IO OriginatedCircuit
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
      _ ->
        fail "Serious internal error (openCircuit)"
 where
  findApplicable ls = loop ls []
   where
    loop [] _ = Nothing
    loop (x : rest) acc
      | ceExitNode x `meetsRestrictions` restricts = Just (x, rest ++ acc)
      | otherwise                                  = loop rest (snoc acc x)
  --
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

-- |Close a circuit. DO NOT CALL THIS. Instead, just drop all references to the
-- structure; we'll worry about this later.
closeCircuit :: HasBackend s => CircuitManager ls s -> OriginatedCircuit -> IO ()
closeCircuit = error "closeCircuit" -- FIXME

-- This is the code that actually builds a circuit, given an appropriate
-- final node.
--
-- FIXME: Make sure that we don't use two routers within the same family.
-- FIXME: Make sure that we don't use two routers within the same /16 subnet.
-- FIXME: Use the path selection weighting criteria in path-spec.txt
--
buildNewCircuit :: HasBackend s =>
                   CircuitManager ls s -> RouterDesc -> Int ->
                   IO OriginatedCircuit
buildNewCircuit cm exitNode len =
  do let notExit = [NotRouter exitNode]
     (link, desc, circId) <- newLinkCircuit (cmLinkManager cm) notExit
     cmLog cm ("Built initial link to " ++ show (routerIPv4Address desc) ++
               " with circuit ID " ++ show circId)
     circ <- createCircuit (cmRNG cm) (cmOptions cm) link desc circId
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

cmLog :: HasBackend s => CircuitManager ls s -> (String -> IO ())
cmLog = torLog . cmOptions
