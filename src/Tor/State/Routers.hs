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
import Data.ByteString.Lazy(ByteString, empty, fromStrict)
import Data.Digest.Pure.SHA
import Data.List
import Data.Maybe
import Data.Time
import Data.Word
import System.Locale
import TLS.Certificate
import Tor.DataFormat.Consensus
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
                       | NotRouter RouterDesc

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
      IsStable | "Stable" `elem` routerStatus rtr -> meetsRestrictions x rest
               | otherwise                        -> Nothing
      NotRouter rdesc | isSameRouter rtr rdesc    -> Nothing
                      | otherwise                 -> meetsRestrictions x rest
  --
  isSameRouter r1 r2 = routerSigningKey r1 == routerSigningKey r2

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
