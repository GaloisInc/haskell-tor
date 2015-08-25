{-# LANGUAGE RecordWildCards   #-}
module Tor.State.Routers(
         RouterDB
       , RouterRestriction(..)
       , newRouterDatabase
       , getRouter
       )
 where

import Control.Applicative
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Crypto.Hash.Easy
import Crypto.PubKey.RSA.KeyHash
import Crypto.PubKey.RSA.PKCS15
import Crypto.Random
import Data.Array.Base
import Data.Bits
import Data.Serialize.Get
import Data.ByteString(ByteString,unpack)
import Data.Hourglass
import Data.Hourglass.Now
import Data.List
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Maybe
import Data.Word
import Tor.DataFormat.Consensus
import Tor.DataFormat.TorAddress
import Tor.NetworkStack
import Tor.NetworkStack.Fetch
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Directories

newtype RouterDB = RouterDB (TVar RouterDBVersion)

data RouterDBVersion = RDB {
       rdbRevision      :: Word
     , rdbDirectoryIP   :: String
     , rdbDirectoryPort :: Word16
     , rdbRoutersPulled :: TVar Word
     , rdbRouters       :: TArray Word RouterEntry
     }

data RouterEntry = Unfetched Router
                 | Broken
                 | Fetched RouterDesc

data RouterRestriction = IsStable -- ^Marked with the Stable flag
                       | NotRouter RouterDesc -- ^Is not the given router
                       | NotTorAddr TorAddress -- ^Is not the given address
                       | ExitNode -- ^Is an exit node of some kind
                       | ExitNodeAllowing TorAddress Word16
                         -- ^Is an exit node that allows traffic to the given
                         -- address and port.

-- |Build a new router database. This database will return before it is fully
-- initialized, in order to make general start-up faster. This may mean that
-- some queries of the database will take longer upon initial loading, or when
-- the database is being refreshed periodicatly.
newRouterDatabase :: TorNetworkStack ls s ->
                     DirectoryDB -> (String -> IO ()) ->
                     IO RouterDB
newRouterDatabase ns ddb logMsg =
  do let rdbRevision      = 0
         rdbDirectoryIP   = ""
         rdbDirectoryPort = 0
     rdbRoutersPulled     <- newTVarIO 0
     rdbRouters           <- atomically $ newArray (0,0) Broken
     let rdb = RDB{ .. }
     retval <- newTVarIO rdb
     _ <- forkIO (updateConsensus    ns ddb logMsg retval)
     return (RouterDB retval)

-- |Fetch a router matching the given restrictions. The restrictions list should
-- be thought of an "AND" with a default of True given the empty list. This
-- routine may take awhile to find a suitable entry if the restrictions are
-- cumbersome or if the database is being reloaded.
getRouter :: RouterDB -> [RouterRestriction] -> TorRNG ->
             STM (RouterDesc, TorRNG)
getRouter (RouterDB routerDB) restrictions rng =
  do curdb <- readTVar routerDB
     entriesGotten      <- readTVar (rdbRoutersPulled curdb)
     (_, entriesPossib) <- getBounds (rdbRouters curdb)
     when (entriesGotten < (2 * (entriesPossib `div` 10))) $ retry
     loop (rdbRouters curdb) (entriesPossib + 1) rng
 where
  loop :: TArray Word RouterEntry -> Word -> TorRNG -> STM (RouterDesc, TorRNG)
  loop entries idxMod g =
    do let (randBS, g') = randomBytesGenerate 8 g
       randWord <- fromIntegral <$> runGetSTM getWord64be randBS
       v <- readArray entries (randWord `mod` idxMod)
       case v `meetsRestrictions` restrictions of
         Nothing -> loop entries idxMod g'
         Just v' -> return (v', g')
  --
  runGetSTM getter bstr =
    case runGet getter bstr of
      Left  _ -> retry
      Right x -> return x
  --
  meetsRestrictions   (Unfetched _) _        = Nothing
  meetsRestrictions    Broken       _        = Nothing
  meetsRestrictions   (Fetched rtr) []       = Just rtr
  meetsRestrictions x@(Fetched rtr) (r:rest) =
    case r of
      IsStable | "Stable" `elem` routerStatus rtr  -> meetsRestrictions x rest
               | otherwise                         -> Nothing
      NotRouter rdesc | isSameRouter rtr rdesc     -> Nothing
                      | otherwise                  -> meetsRestrictions x rest
      NotTorAddr taddr | isSameAddr taddr rtr      -> Nothing
                       | otherwise                 -> meetsRestrictions x rest
      ExitNode | allowsExits (routerExitRules rtr) -> meetsRestrictions x rest
               | otherwise                         -> Nothing
      ExitNodeAllowing a p
            | allowsExit (routerExitRules rtr) a p -> meetsRestrictions x rest
            | otherwise                            -> Nothing
  --
  isSameRouter r1 r2 = routerSigningKey r1 == routerSigningKey r2
  --
  isSameAddr (IP4 x) r = x == routerIPv4Address r
  isSameAddr (IP6 x) r = x `elem` map fst (routerAlternateORAddresses r)
  isSameAddr _       _ = False
  --
  allowsExits (ExitRuleReject AddrSpecAll PortSpecAll : _) = False
  allowsExits _ = True
  --
  allowsExit [] _ _ = True -- "if no rule matches, the address wil be accepted"
  allowsExit (ExitRuleAccept addrrule portrule : rest) addr port
    | addrMatches addr addrrule && portMatches port portrule = True
    | otherwise = allowsExit rest addr port
  allowsExit (ExitRuleReject addrrule portrule : rest) addr port
    | addrMatches addr addrrule && portMatches port portrule = False
    | otherwise = allowsExit rest addr port
  --
  portMatches _ PortSpecAll           = True
  portMatches p (PortSpecRange p1 p2) = (p >= p1) && (p <= p2)
  portMatches p (PortSpecSingle p')   = p == p'
  --
  addrMatches :: TorAddress -> AddrSpec -> Bool
  addrMatches (Hostname _)          _                     = False
  addrMatches (TransientError _)    _                     = False
  addrMatches (NontransientError _) _                     = False
  addrMatches _                     AddrSpecAll           = True
  addrMatches (IP4 addr)            (AddrSpecIP4 addr')   = addr == addr'
  addrMatches (IP4 addr)            (AddrSpecIP4Mask a m) = ip4in' addr a m
  addrMatches (IP4 addr)            (AddrSpecIP4Bits a b) = ip4in  addr a b
  addrMatches (IP4 _)               (AddrSpecIP6 _)       = False
  addrMatches (IP4 _)               (AddrSpecIP6Bits _ _) = False
  addrMatches (IP6 _)               (AddrSpecIP4 _)       = False
  addrMatches (IP6 _)               (AddrSpecIP4Mask _ _) = False
  addrMatches (IP6 _)               (AddrSpecIP4Bits _ _) = False
  addrMatches (IP6 addr)            (AddrSpecIP6 addr')   = addr `ip6eq` addr'
  addrMatches (IP6 addr)            (AddrSpecIP6Bits a b) = ip6in addr a b
  --
  ip4in' addr addr' mask =
     masked (unAddr IP4 addr) mask' == masked (unAddr IP4 addr') mask'
    where mask' = generateMaskFromMask mask
  ip4in  addr addr' bits =
     masked (unAddr IP4 addr) mask == masked (unAddr IP4 addr') mask
    where mask  = generateMaskFromBits bits 4
  ip6in  addr addr' bits =
     masked (unAddr IP6 addr) mask == masked (unAddr IP6 addr') mask
    where mask  = generateMaskFromBits bits 16
  ip6eq  addr1 addr2 = expandIPv6 addr1 == expandIPv6 addr2
  --
  unAddr b = unpack . torAddressByteString . b
  generateMaskFromMask x = unAddr IP4 x
  generateMaskFromBits :: Int -> Int -> [Word8]
  generateMaskFromBits bits len
    | len == 0  = []
    | bits == 0 = 0   : generateMaskFromBits bits       (len - 1)
    | bits >= 8 = 255 : generateMaskFromBits (bits - 8) (len - 1)
    | otherwise = (255 `shiftL` (8 - len)) : generateMaskFromBits 0 (len - 1)
  masked a m = zipWith xor a m
  expandIPv6 = unAddr IP6

-- |The thread that updates the consensus document over time.
updateConsensus :: TorNetworkStack ls s ->
                   DirectoryDB -> (String -> IO ()) ->
                   TVar RouterDBVersion ->
                   IO ()
updateConsensus ns ddb logMsg rdbTV = runUpdate =<< drgNew
 where
  runUpdate rng =
    do logMsg ("Starting consensus document update.")
       (dir, rng') <- atomically (getRandomDirectory rng ddb)
       logMsg ("Using directory " ++ dirNickname dir ++ " for consensus.")
       mc <- fetch ns (dirAddress dir) (dirDirPort dir) ConsensusDocument
       case mc of
         Left err ->
           do logMsg ("Couldn't get consensus document: " ++ err)
              logMsg ("Retrying.")
              runUpdate rng'
         Right (consensus, sha1dig, sha256dig) ->
           do let sigs = conSignatures consensus
              forM_ (conAuthorities consensus) (addDirectory ns logMsg ddb)
              validSigs <- getValidSignatures ddb sha1dig sha256dig sigs
              if length validSigs < 5
                 then do logMsg ("Couldn't find 5 valid signatures. Retrying.")
                         runUpdate rng'
                 else do logMsg ("Found 5 or more valid signatures: " ++
                                 intercalate ", " validSigs)
                         rdb <- atomically $
                           do curVersion <- rdbRevision <$> readTVar rdbTV
                              let revision' = curVersion + 1
                                  routers   = filter goodRouter
                                                (conRouters consensus)
                                  num       = fromIntegral (length routers)
                                  addr      = dirAddress dir
                                  port      = dirDirPort dir
                              cnt <- newTVar 0
                              arr <- newListArray (0, num - 1)
                                                  (map Unfetched routers)
                              let rdb = RDB revision' addr port cnt arr
                              writeTVar rdbTV rdb
                              return rdb
                         _ <- forkIO (translateConsensus ns logMsg rdb)
                         let (nextTime, rng'') = computeNextTime consensus rng'
                         logMsg ("Will reload consensus at "++showTime nextTime)
                         waitUntil nextTime
                         logMsg "Consensus expired. Reloading."
                         runUpdate rng''
  --
  goodRouter r =
    let s = rtrStatus r
    in ("Valid" `elem` s) && ("Running" `elem` s) && ("Fast" `elem` s)
  showTime = timePrint [Format_Hour, Format_Text ':', Format_Minute]


-- |The consensus document we get from our directory servers is handy, but
-- doesn't contain all the information we need. This function goes through all
-- the entries and updates them with better data. This function is launched as a
-- thread whenever a new consensus document is created.
translateConsensus :: TorNetworkStack ls s -> (String -> IO ()) ->
                      RouterDBVersion ->
                      IO ()
translateConsensus ns logMsg rdb =
  do (minIdx, maxIdx) <- atomically (getBounds arr)
     logMsg "Downloading router descriptors."
     mtable <- fetch ns (rdbDirectoryIP rdb) (rdbDirectoryPort rdb) Descriptors
     case mtable of
       Left err ->
         do logMsg ("Failed to get router descriptors: " ++ err)
            translateConsensus ns logMsg rdb
       Right table ->
         do logMsg "Loading router descriptor table."
            run minIdx maxIdx table
 where
  run startIdx maxIdx table
    | startIdx > maxIdx =
        do cnt <- atomically (readTVar (rdbRoutersPulled rdb))
           logMsg ("Router descriptor table complete. " ++ show cnt ++
                   " of " ++ show maxIdx ++ " routers available.")
    | otherwise         =
        do join $ atomically $ processEntry startIdx table
           when ((startIdx `mod` 500) == 0) $
             do let percD = fromIntegral startIdx / fromIntegral maxIdx :: Double
                    perc  = round (100 * percD)
                logMsg ("Fetched " ++ show (perc :: Int) ++ "% of " ++
                        show (maxIdx + 1) ++ " router entries.")
           run (succ startIdx) maxIdx table
  --
  processEntry x table =
    do cur <- readArray arr x
       case cur of
         Unfetched rtr ->
           case Map.lookup (rtrIdentity rtr) table of
             Nothing ->
               do writeArray arr x Broken
                  return (return ())
             Just d ->
               do writeArray arr x (Fetched d{routerStatus = rtrStatus rtr})
                  modifyTVar' (rdbRoutersPulled rdb) succ
                  return (return ())
         Broken ->
           return (logMsg "Internal Error: Broken during translate.")
         Fetched _ ->
           return (logMsg "Internal Error: Fetched during translate.")
  --
  arr = rdbRouters rdb

getValidSignatures :: DirectoryDB -> ByteString -> ByteString ->
                      [(Bool, ByteString, ByteString, ByteString)] ->
                      IO [String]
getValidSignatures ddb sha1dig sha256dig sigs =
  catMaybes <$>
    (forM sigs $ \ (isSHA1, ident, _, sig) ->
       do mdir <- atomically (findDirectory ident ddb)
          -- FIXME: Do something more useful in the failure cases?
          case mdir of
            Nothing -> return Nothing
            Just dir ->
              do let digest = if isSHA1 then sha1dig else sha256dig
                     key    = dirSigningKey dir
                 if verify noHash key digest sig
                   then return (Just (dirNickname dir))
                   else return Nothing)

computeNextTime :: DRG g =>
                   Consensus -> g ->
                   (DateTime, g)
computeNextTime consensus g = (timeAdd lowest diffAmt, g')
 where
  validAfter = conValidAfter consensus
  freshUntil = conFreshUntil consensus
  validUntil = conValidUntil consensus
  interval   = timeDiff freshUntil validAfter
  lowest     = timeAdd freshUntil (mulSeconds 0.75 interval)
  interval'  = timeDiff validUntil lowest
  highest    = timeAdd lowest (mulSeconds 0.875 interval')
  diff       = timeDiff highest lowest
  (bstr, g') = randomBytesGenerate 8 g
  Right amt  = runGet ((Seconds . fromIntegral)`fmap` getWord64be) bstr
  diffAmt    = amt `mod` diff
  --
  mulSeconds :: Double -> Seconds -> Seconds
  mulSeconds f (Seconds s) = Seconds (round (f * fromIntegral s)) 

waitUntil :: DateTime -> IO ()
waitUntil time =
  do now <- getCurrentTime
     if now > time
        then return ()
        else do threadDelay 100000 -- (5 * 60 * 1000000) -- 5 minutes
                waitUntil time
