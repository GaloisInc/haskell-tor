{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.State(
         TorState
       , RouterRestriction(..)
       , RNG.TorRNG
       , initializeTorState
       , logMsg
       , addLocalAddress
       , getLocalAddresses
       , getLocalRouterDesc
       , getNetworkStack
       , Tor.State.getRouter
       , getSigningCredentials
       , Tor.State.withRNG
       , Tor.State.withRNGSTM
       )
 where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Data.ByteString.Lazy(empty)
import Data.Time
import Data.X509
import Tor.DataFormat.TorAddress
import Tor.NetworkStack
import Tor.Options
import Tor.RouterDesc
import Tor.State.Credentials
import Tor.State.Directories
import Tor.State.RNG as RNG
import Tor.State.Routers

data TorState ls s = TorState {
       tsRNG            :: RNG
     , tsNetwork        :: TorNetworkStack ls s
     , tsLogger         :: String -> IO ()
     , tsCredentials    :: Credentials
     , tsDirectories    :: DirectoryDB
     , tsRouters        :: RouterDB
     , tsAddresses      :: TVar [TorAddress]
     , tsBaseRouterDesc :: RouterDesc
     }

initializeTorState :: TorNetworkStack ls s -> (String -> IO ()) -> [Flag] ->
                      IO (TorState ls s)
initializeTorState tsNetwork tsLogger flags =
  do now           <- getCurrentTime
     tsRNG         <- newRNGState tsLogger
     tsDirectories <- newDirectoryDatabase tsNetwork tsLogger defaultDirectories
     tsCredentials <- newCredentials tsRNG tsLogger
     tsRouters     <- newRouterDatabase tsNetwork tsRNG tsDirectories tsLogger
     tsAddresses   <- newTVarIO []
     let tsBaseRouterDesc = RouterDesc {
           routerNickname                = getNickname flags
         , routerIPv4Address             = ""
         , routerORPort                  = getOnionPort flags
         , routerDirPort                 = Nothing
         , routerParseLog                = []
         , routerAvgBandwidth            = 0
         , routerBurstBandwidth          = 0
         , routerObservedBandwidth       = 0
         , routerPlatformName            = "Haskell"
         , routerEntryPublished          = now
         , routerFingerprint             = empty
         , routerHibernating             = False
         , routerUptime                  = Nothing
         , routerOnionKey                = undefined
         , routerNTorOnionKey            = Nothing
         , routerSigningKey              = undefined
         , routerExitRules               = []
         , routerIPv6Policy              = Left []
         , routerSignature               = empty
         , routerContact                 = getContactInfo flags
         , routerFamily                  = [] -- FIXME?
         , routerReadHistory             = Nothing
         , routerWriteHistory            = Nothing
         , routerCachesExtraInfo         = False
         , routerExtraInfoDigest         = Nothing
         , routerHiddenServiceDir        = Nothing
         , routerLinkProtocolVersions    = [4]
         , routerCircuitProtocolVersions = [1]
         , routerAllowSingleHopExits     = False
         , routerAlternateORAddresses    = []
         , routerStatus                  = []
         }
     return TorState{..}

-- -----------------------------------------------------------------------------

logMsg :: TorState ls s -> String -> IO ()
logMsg = tsLogger

addLocalAddress :: TorState ls s -> TorAddress -> IO ()
addLocalAddress _ (TransientError _) = return ()
addLocalAddress _ (NontransientError _) = return ()
addLocalAddress ts x =
  do msg <- atomically $ do current <- readTVar (tsAddresses ts)
                            if x `elem` current
                               then return ""
                               else do writeTVar (tsAddresses ts) (x : current)
                                       return ("Added new address: " ++
                                               unTorAddress x)
     unless (msg == "") $
       logMsg ts msg

getLocalAddresses :: TorState ls s -> IO [TorAddress]
getLocalAddresses = atomically . readTVar . tsAddresses

getLocalRouterDesc :: TorState ls s -> IO RouterDesc
getLocalRouterDesc torst =
  do now <- getCurrentTime
     (ipaddr, sigc, onionc, acts) <-
       atomically $
         do ipaddr <- readTVar (tsAddresses torst)
            (sigcert, _, next1) <- getSigningKey (tsCredentials torst) now
            (oncert,  _, next2) <- getOnionKey   (tsCredentials torst) now
            return (ipaddr, sigcert, oncert, [next1, next2])
     runActions torst acts
     return (tsBaseRouterDesc torst){ routerIPv4Address = getIPv4Address ipaddr
                                    , routerOnionKey    = getPublicKey onionc
                                    , routerSigningKey  = getPublicKey sigc
                                    }
 where
  getIPv4Address []          = error "Attempt to build desc w/o IP4 address!"
  getIPv4Address ((IP4 x):_) = x
  getIPv4Address (_:rest)    = getIPv4Address rest
  getPublicKey cert =
    case certPubKey (signedObject (getSigned cert)) of
      PubKeyRSA k -> k
      _           -> error "Illegal key type in certificate."


getNetworkStack :: TorState ls s -> TorNetworkStack ls s
getNetworkStack = tsNetwork

getRouter :: TorState ls s -> [RouterRestriction] -> IO RouterDesc
getRouter torst rests =
  atomically $ Tor.State.Routers.getRouter (tsRouters torst) rests (tsRNG torst)

getSigningCredentials :: TorState ls s -> IO (SignedCertificate, PrivKey)
getSigningCredentials s =
  do now <- getCurrentTime
     (cert, priv, next) <- atomically (getSigningKey (tsCredentials s) now)
     runActions s [next]
     return (cert, priv)

runActions :: TorState ls s -> [Maybe (RNG -> STM String)] -> IO ()
runActions _ []                = return ()
runActions s (Nothing:rest)    = runActions s rest
runActions s (Just act : rest) =
  do _ <- forkIO $ do msg <- atomically (act (tsRNG s))
                      logMsg s msg
     runActions s rest


withRNG :: TorState ls s -> (TorRNG -> (a, TorRNG)) -> IO a
withRNG s f = RNG.withRNG (tsRNG s) f

withRNGSTM :: TorState ls s -> (TorRNG -> STM (a, TorRNG)) -> STM a
withRNGSTM s f = RNG.withRNGSTM (tsRNG s) f

-- ----------------------------------------------------------------------------

-- This is pretty much a copy and paste from the Tor reference source code, and
-- should remain that way in order to make updating it as simple as possible.
defaultDirectories :: [String]
defaultDirectories = [
    "moria1 orport=9101 " ++
      "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 " ++
      "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
    "tor26 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 " ++
      "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
    "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 " ++
      "194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
    "Tonga orport=443 bridge 82.94.251.203:80 " ++
      "4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
--    "turtles orport=9090 " ++
--      "v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 " ++
--      "76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
    "gabelmoo orport=443 " ++
      "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 " ++
      "212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
    "dannenberg orport=443 " ++
      "v3ident=585769C78764D58426B8B52B6651A5A71137189A " ++
      "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
    "urras orport=80 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C " ++
      "208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
--    "maatuska orport=80 " ++
--      "v3ident=49015F787433103580E3B66A1707A00E60F2D15B " ++
--      "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
    "Faravahar orport=443 " ++
      "v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 " ++
      "154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC"
  ]
