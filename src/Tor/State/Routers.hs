{-# LANGUAGE RecordWildCards   #-}
module Tor.State.Routers(
         RouterDB
       , RouterRestriction(..)
       , newRouterDatabase
       , getRouter
       )
 where

import Codec.Crypto.RSA.Pure
import Control.Applicative hiding (empty)
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Crypto.Random
import Data.Array.Base
import Data.Binary.Get
import Data.Bits
import Data.ByteString.Lazy(ByteString, empty, fromStrict, unpack)
import Data.Digest.Pure.SHA
import Data.List
import Data.Maybe
import Data.Time
import Data.Word
import System.Locale
import TLS.Certificate
import Tor.DataFormat.Consensus
import Tor.DataFormat.TorAddress
import Tor.NetworkStack
import Tor.NetworkStack.Fetch
import Tor.RouterDesc
import Tor.State.Directories
import Tor.State.RNG

newtype RouterDB = RouterDB (TVar RouterDBVersion)

data RouterDBVersion = RDB {
       rdbRevision      :: Word
     , rdbDirectoryIP   :: String
     , rdbDirectoryPort :: Word16
     , rdbRouters       :: TArray Word RouterEntry
     }

data RouterEntry = Unfetched Router
                 | Fetching
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
                     RNG -> DirectoryDB -> (String -> IO ()) ->
                     IO RouterDB
newRouterDatabase ns rng ddb logMsg =
  do let rdbRevision = 0
     rdbRouters  <- atomically $ newArray (0,0) undefined
     let rdbDirectoryIP = undefined
         rdbDirectoryPort = undefined
     let rdb = RDB{ .. }
     retval <- newTVarIO rdb
     updateConsensus ns rng ddb logMsg retval
     return (RouterDB retval)

-- |Fetch a router matching the given restrictions. The restrictions list should
-- be thought of an "AND" with a default of True given the empty list. This
-- routine may take awhile to find a suitable entry if the restrictions are
-- cumbersome or if the database is being reloaded.
getRouter :: RouterDB -> [RouterRestriction] -> RNG -> STM RouterDesc
getRouter (RouterDB routerdb) restrictions rng = withRNGSTM rng get
 where
  get :: TorRNG -> STM (RouterDesc, TorRNG)
  get g =
    do curdb <- readTVar routerdb
       case genBytes 8 g of
         Left _ -> retry
         Right (bstr, g') ->
           do let i = fromIntegral (runGet getWord64be (fromStrict bstr))
              (_, maxIdx) <- getBounds (rdbRouters curdb)
              v <- readArray (rdbRouters curdb) (i `mod` (maxIdx + 1))
              case v `meetsRestrictions` restrictions of
                Nothing -> get g'
                Just v' -> return (v', g')
  --
  meetsRestrictions   (Unfetched _) _        = Nothing
  meetsRestrictions    Fetching     _        = Nothing
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

updateConsensus :: TorNetworkStack ls s ->
                   RNG -> DirectoryDB -> (String -> IO ()) ->
                   TVar RouterDBVersion ->
                   IO ()
updateConsensus ns rng ddb logMsg rdbTV =
  do dir <- atomically (getRandomDirectory rng ddb)
     logMsg ("Using directory " ++ dirNickname dir ++ " for consensus.")
     mconsensus <- fetch ns (dirAddress dir) (dirDirPort dir) ConsensusDocument
     case mconsensus of
       Left err ->
         do logMsg ("Couldn't get consensus document: " ++ err)
            logMsg ("Retrying.")
            updateConsensus ns rng ddb logMsg rdbTV
       Right (consensus, sha1dig, sha256dig) ->
         do let sigs = conSignatures consensus
            forM_ (conAuthorities consensus) (addDirectory ns logMsg ddb)
            validSigs <- getValidSignatures ddb sha1dig sha256dig sigs
            if length validSigs < 5
               then do logMsg ("Couldn't find 5 valid signatures. Retrying.")
                       updateConsensus ns rng ddb logMsg rdbTV
               else do logMsg ("Found 5 or more valid signatures: " ++
                               intercalate ", " validSigs)
                       atomically $
                         do curVersion <- rdbRevision <$> readTVar rdbTV
                            let revision' = curVersion + 1
                                routers   = filter goodRouter
                                              (conRouters consensus)
                                num       = fromIntegral (length routers)
                                addr      = dirAddress dir
                                port      = dirDirPort dir
                            arr <- newListArray (0, num - 1)
                                                (map Unfetched routers)
                            writeTVar rdbTV (RDB revision' addr port arr)
                       nextTime <- withRNG rng (computeNextTime consensus)
                       logMsg ("Will reload consensus at " ++ showTime nextTime)
                       _ <- forkIO $ do waitUntil nextTime
                                        logMsg "Consensus expired. Reloading."
                                        updateConsensus ns rng ddb logMsg rdbTV
                       _ <- forkIO $ translateConsensus ns logMsg rdbTV
                       return ()
 where
  goodRouter r =
    let s = rtrStatus r
    in ("Valid" `elem` s) && ("Running" `elem` s) && ("Fast" `elem` s)

translateConsensus :: TorNetworkStack ls s -> (String -> IO ()) ->
                      TVar RouterDBVersion ->
                      IO ()
translateConsensus ns logMsg rdbTV =
  do rdb <- readTVarIO rdbTV
     (_, num) <- atomically $ getBounds (rdbRouters rdb)
     translate (rdbRevision rdb) 0 (num + 1) (rdbRouters rdb)
 where
  translate :: Word -> Word -> Word -> TArray Word RouterEntry -> IO ()
  translate _ x total _ | x == total =
    logMsg "Completed download of router descriptions."
  translate rev x total arr =
    do rdb <- readTVarIO rdbTV
       -- there's a bit of race condition here, but it shouldn't be dramatic.
       -- at worse it will cause a brief, temporary overallocation of memory.
       unless (rdbRevision rdb /= rev) $
         do act <- atomically $ do cur <- readArray arr x
                                   case cur of
                                     Unfetched r ->
                                       do writeArray arr x Fetching
                                          return (fetchAndUpdate rdb x arr r)
                                     _ ->
                                       return (return ())
            act
            when (x `mod` 100 == 0) $
              do let percD = fromIntegral x / fromIntegral total :: Double
                     perc  = round (100 * percD)
                 logMsg ("Fetched " ++ show (perc :: Int) ++ "% of " ++
                         show total ++ " router entries.")
            translate rev (x + 1) total arr
  --
  fetchAndUpdate rdb x arr r =
    do let ip = rdbDirectoryIP rdb
           port = rdbDirectoryPort rdb
       mdesc <- fetch ns ip port (Descriptor (rtrDigest r))
       case mdesc of
         Left err ->
           do logMsg ("Failure reading router description: " ++ err)
              atomically $ writeArray arr x Broken
         Right [d] | rtrIdentity r /= keyHash' sha1 (routerSigningKey d) ->
           do logMsg ("Router description identity doesn't match " ++
                      "signing key. Ignoring.")
              atomically $ writeArray arr x Broken
         Right [d] ->
           atomically $ writeArray arr x (Fetched d{routerStatus = rtrStatus r})
         Right _ ->
           do logMsg ("Too many/few descriptions for digest key.")
              atomically $ writeArray arr x Broken

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
                 case rsassa_pkcs1_v1_5_verify hashE key digest sig of
                   Left  _     -> return Nothing
                   Right False -> return Nothing
                   Right True  -> return (Just (dirNickname dir)))
 where hashE = HashInfo empty id

computeNextTime :: CryptoRandomGen g =>
                   Consensus -> g ->
                   (UTCTime, g)
computeNextTime consensus g =
  let validAfter = conValidAfter consensus
      freshUntil = conFreshUntil consensus
      validUntil = conValidUntil consensus
      interval   = diffUTCTime freshUntil validAfter
      lowest     = addUTCTime (0.75 * interval) freshUntil
      interval'  = diffUTCTime validUntil lowest
      highest    = addUTCTime (0.875 * interval') lowest
      diff       = diffUTCTime highest lowest
      diff'      = fromIntegral (fromEnum diff)
  in case genBytes 8 g of
       Left _ -> computeNextTime consensus g
       Right (bstr, g') ->
         let amt = runGet getWord64be (fromStrict bstr)
             diffAmt = toEnum (fromIntegral (amt `mod` diff'))
         in (addUTCTime diffAmt lowest, g')

waitUntil :: UTCTime -> IO ()
waitUntil time =
  do now <- getCurrentTime
     if now > time
        then return ()
        else do threadDelay 100000 -- (5 * 60 * 1000000) -- 5 minutes
                waitUntil time

showTime :: UTCTime -> String
showTime = formatTime defaultTimeLocale "%d%b%Y %X"
