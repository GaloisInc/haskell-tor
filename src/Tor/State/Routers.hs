module Tor.State.Routers(
         RouterDB
       , newRouterDatabase
       )
 where

import Codec.Crypto.RSA.Pure
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.ByteString.Lazy(empty,fromStrict)
import Data.Digest.Pure.SHA
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
         do let _  = sha1dig :: Digest SHA1State
                _  = sha256dig :: Digest SHA256State
            forM_ (conAuthorities consensus) (addDirectory ns logMsg ddb)
            forM_ (conSignatures consensus) $ \ (isSHA1, ident, _, sig) ->
              do mdir <- atomically (findDirectory ident ddb)
                 -- FIXME: Do something more useful in the failure cases.
                 case mdir of
                   Nothing ->
                     logMsg ("Couldn't find directory for signature with " ++
                             "fingerprint " ++ show ident)
                   Just dir' ->
                     do let digest = if isSHA1 then bytestringDigest sha1dig
                                            else bytestringDigest sha256dig
                            key    = dirSigningKey dir'
                        case rsassa_pkcs1_v1_5_verify hashE key digest sig of
                          Left err ->
                            logMsg ("Couldn't validate signature for ident " ++
                                    show ident ++ ": " ++ show err)
                          Right False ->
                            logMsg ("Bad signature for ident " ++ show ident)
                          Right True ->
                            logMsg ("Signature validated by "++dirNickname dir')
            atomically (writeTVar consensusTV consensus)
            nextTime <- withRNG rng (computeNextTime consensus)
            logMsg ("Will reload consensus at " ++ showTime nextTime)
            _ <- forkIO $ do waitUntil nextTime
                             updateConsensus ns rng ddb logMsg consensusTV
            return ()
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
