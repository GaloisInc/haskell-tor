module Tor.State.LinkManager(
         LinkManager
       , newLinkManager
       , newLinkCircuit
       , setIncomingLinkHandler
       )
 where

import Control.Concurrent
import Control.Monad
import Crypto.Random
import Data.Maybe
import Data.Word
import Network.TLS hiding (Credentials)
import Tor.Link
import Tor.NetworkStack
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Credentials
import Tor.State.Routers

data HasBackend s => LinkManager ls s = LinkManager {
       lmNetworkStack        :: TorNetworkStack ls s
     , lmRouterDB            :: RouterDB
     , lmCredentials         :: Credentials
     , lmIdealLinks          :: Int
     , lmMaxLinks            :: Int
     , lmLog                 :: String -> IO ()
     , lmRNG                 :: MVar TorRNG
     , lmLinks               :: MVar [TorLink]
     , lmIncomingLinkHandler :: MVar (TorLink -> IO ())
     }

newLinkManager :: HasBackend s =>
                  TorOptions ->
                  TorNetworkStack ls s ->
                  RouterDB -> Credentials ->
                  IO (LinkManager ls s)
newLinkManager o ns routerDB creds =
  do rngMV     <- newMVar =<< drgNew
     linksMV   <- newMVar []
     ilHndlrMV <- newMVar (const (return ()))
     let lm = LinkManager {
                lmNetworkStack        = ns
              , lmRouterDB            = routerDB
              , lmCredentials         = creds
              , lmIdealLinks          = idealLinks
              , lmMaxLinks            = maxLinks
              , lmLog                 = torLog o
              , lmRNG                 = rngMV
              , lmLinks               = linksMV
              , lmIncomingLinkHandler = ilHndlrMV
              }
     when (isRelay || isExit) $
       do lsock <- listen ns orPort
          lmLog lm ("Waiting for Tor connections on port " ++ show orPort)
          forkIO_ $ forever $
            do (sock, addr) <- accept ns lsock
               forkIO_ $
                 do link <- acceptLink creds routerDB rngMV (torLog o) sock addr
                    modifyMVar_ linksMV (return . (link:))
     return lm
 where
  isRelay    = isJust (torRelayOptions o)
  isExit     = isJust (torExitOptions o)
  orPort     = maybe 9374 torOnionPort (torRelayOptions o)
  idealLinks = maybe 3 torTargetLinks (torEntranceOptions o)
  maxLinks   = maybe 3 torMaximumLinks (torRelayOptions o)

newLinkCircuit :: HasBackend s =>
                  LinkManager ls s -> [RouterRestriction] ->
                  IO (TorLink, RouterDesc, Word32)
newLinkCircuit lm restricts =
  modifyMVar (lmLinks lm) $ \ curLinks ->
    if length curLinks >= lmIdealLinks lm
       then getExistingLink curLinks []
       else buildNewLink    curLinks
 where
  getExistingLink :: [TorLink] -> [TorLink] ->
                     IO ([TorLink], (TorLink, RouterDesc, Word32))
  getExistingLink []                 acc = buildNewLink acc
  getExistingLink (link:rest) acc
    | Just rd <- linkRouterDesc link
    , rd `meetsRestrictions` restricts   =
        do circId <- modifyMVar (lmRNG lm) (linkNewCircuitId link)
           return (rest ++ acc, (link, rd, circId))
    | otherwise                          =
        getExistingLink rest (acc ++ [link])
  --
  buildNewLink :: [TorLink] ->
                  IO ([TorLink], (TorLink, RouterDesc, Word32))
  buildNewLink curLinks =
    do entranceDesc <- modifyMVar (lmRNG lm)
                         (getRouter (lmRouterDB lm) restricts)
       link         <- initLink (lmNetworkStack lm) (lmCredentials lm)
                         (lmRNG lm) (lmLog lm)
                         entranceDesc
       circId       <- modifyMVar (lmRNG lm) (linkNewCircuitId link)
       return (curLinks ++ [link], (link, entranceDesc, circId))

setIncomingLinkHandler :: HasBackend s =>
                          LinkManager ls s -> (TorLink -> IO ()) ->
                          IO ()
setIncomingLinkHandler lm h =
  modifyMVar_ (lmIncomingLinkHandler lm) (const (return h))

forkIO_ :: IO () -> IO ()
forkIO_ m = forkIO m >> return ()
