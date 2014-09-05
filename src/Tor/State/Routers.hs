module Tor.State.Routers(
         RouterDB
       , newRouterDatabase
       )
 where

import Codec.Crypto.RSA.Pure
import Control.Applicative hiding (empty)
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.ByteString.Lazy(ByteString, empty, fromStrict)
import Data.Digest.Pure.SHA
import Data.List
import Data.Maybe
import Data.Time
import System.Locale
import Tor.DataFormat.Consensus
import Tor.NetworkStack
import Tor.NetworkStack.Fetch
import Tor.State.Directories
import Tor.State.RNG

newtype RouterDB = RouterDB (TVar Consensus)

newRouterDatabase :: TorNetworkStack ls s ->
                     RNG -> DirectoryDB -> (String -> IO ()) ->
                     IO RouterDB
newRouterDatabase ns rng ddb logMsg =
  do consensusTV <- newTVarIO undefined
     updateConsensus ns rng ddb logMsg consensusTV
     return (RouterDB consensusTV)

updateConsensus :: TorNetworkStack ls s ->
                   RNG -> DirectoryDB -> (String -> IO ()) ->
                   TVar Consensus ->
                   IO ()
updateConsensus ns rng ddb logMsg consensusTV =
  do dir <- atomically (getRandomDirectory rng ddb)
     logMsg ("Using directory " ++ dirNickname dir ++ " for consensus.")
     mconsensus <- fetch ns (dirAddress dir) (dirDirPort dir) ConsensusDocument
     case mconsensus of
       Left err ->
         do logMsg ("Couldn't get consensus document: " ++ err)
            logMsg ("Retrying.")
            updateConsensus ns rng ddb logMsg consensusTV
       Right (consensus, sha1dig, sha256dig) ->
         do let _    = sha1dig :: Digest SHA1State
                _    = sha256dig :: Digest SHA256State
                sigs = conSignatures consensus
            forM_ (conAuthorities consensus) (addDirectory ns logMsg ddb)
            validSigs <- getValidSignatures ddb sha1dig sha256dig sigs
            if length validSigs < 5
               then do logMsg ("Couldn't find 5 valid signatures. Retrying.")
                       updateConsensus ns rng ddb logMsg consensusTV
               else do logMsg ("Found 5 or more valid signautres: " ++
                               intercalate ", " validSigs)

                       atomically (writeTVar consensusTV consensus)
                       nextTime <- withRNG rng (computeNextTime consensus)
                       logMsg ("Will reload consensus at " ++ showTime nextTime)
                       _ <- forkIO $ do waitUntil nextTime
                                        updateConsensus ns rng ddb
                                                        logMsg consensusTV
                       return ()

getValidSignatures :: DirectoryDB -> Digest SHA1State -> Digest SHA256State ->
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
              do let digest = if isSHA1 then bytestringDigest sha1dig
                                        else bytestringDigest sha256dig
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
        else threadDelay (5 * 60 * 1000000) -- 5 minutes

showTime :: UTCTime -> String
showTime = formatTime defaultTimeLocale "%d%b%Y %X"
