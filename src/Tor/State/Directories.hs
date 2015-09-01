module Tor.State.Directories(
         Directory(..)
       , DirectoryDB
       , newDirectoryDatabase
       , getRandomDirectory
       , findDirectory
       , addDirectory
       )
 where

import Control.Concurrent
import Crypto.PubKey.RSA
import Crypto.Random
import Control.Monad
import Data.ByteString(uncons)
import Data.ByteString(ByteString)
import Data.ByteString.Char8(pack)
import Data.Either
import Data.Hourglass
import Data.List hiding (uncons)
import Data.Maybe
import Data.Word
import Tor.DataFormat.Consensus
import Tor.DataFormat.DefaultDirectory
import Tor.DataFormat.DirCertInfo
import Tor.NetworkStack
import Tor.NetworkStack.Fetch

data Directory = Directory {
       dirNickname    :: String
     , dirIsBridge    :: Bool
     , dirAddress     :: String
     , dirOnionPort   :: Word16
     , dirDirPort     :: Word16
     , dirV3Ident     :: Maybe ByteString
     , dirFingerprint :: ByteString
     , dirPublished   :: DateTime
     , dirExpires     :: DateTime
     , dirIdentityKey :: PublicKey
     , dirSigningKey  :: PublicKey
     }
 deriving (Show)

newtype DirectoryDB = DDB (MVar [Directory])

newDirectoryDatabase :: TorNetworkStack ls s -> (String -> IO ()) ->
                        [String] ->
                        IO DirectoryDB
newDirectoryDatabase ns logMsg defaultStrs =
  do let defaultDirs = rights (map (parseDefaultDirectory . pack) defaultStrs)
     dirs <- forM defaultDirs $ \ d ->
               do logMsg ("Fetching credentials for default directory " ++
                          (ddirNickname d) ++ " [" ++ ddirAddress d ++ ":" ++
                          show (ddirDirPort d) ++ "]")
                  e <- fetch ns (ddirAddress d) (ddirDirPort d) KeyCertificate
                  case (e, ddirV3Ident d) of
                    (Left err, _) ->
                      do logMsg ("Fetch failed: " ++ err)
                         return Nothing
                    (Right _, Nothing) ->
                      do logMsg ("Ignoring directory w/o V3Ident.")
                         return Nothing
                    (Right i, Just v3ident) | v3ident /= dcFingerprint i ->
                      do logMsg ("Weird: fingerprint mismatch. Ignoring dir.")
                         return Nothing
                    (Right i, Just _) ->
                      do return $ Just $ Directory {
                           dirNickname = ddirNickname d
                         , dirIsBridge = ddirIsBridge d
                         , dirAddress = ddirAddress d
                         , dirOnionPort = ddirOnionPort d
                         , dirDirPort = ddirDirPort d
                         , dirV3Ident = ddirV3Ident d
                         , dirFingerprint = ddirFingerprint d
                         , dirPublished = dcPublished i
                         , dirExpires = dcExpires i
                         , dirIdentityKey = dcIdentityKey i
                         , dirSigningKey = dcSigningKey i
                         }
     let loadedDirs = catMaybes dirs
     logMsg (show (length loadedDirs) ++ " of " ++ show (length defaultStrs) ++
             " default directories loaded.")
     DDB `fmap` newMVar loadedDirs

getRandomDirectory :: DRG g => g -> DirectoryDB -> IO (Directory, g)
getRandomDirectory g ddb@(DDB dirlsMV) =
  do ls <- readMVar dirlsMV
     let (bstr, g') = randomBytesGenerate 1 g
     case uncons bstr of
       Nothing -> 
         do threadDelay 1000000
            getRandomDirectory g ddb
       Just (x, _) ->
         do let idx = fromIntegral x `mod` length ls
            return (ls !! idx, g')

findDirectory :: ByteString -> DirectoryDB -> IO (Maybe Directory)
findDirectory fprint (DDB dirlsMV) =
  find matchesFingerprint `fmap` readMVar dirlsMV
 where
  matchesFingerprint dir =
    case dirV3Ident dir of
      Nothing -> False
      Just x  -> x == fprint

addDirectory :: TorNetworkStack ls s -> (String -> IO ()) ->
                DirectoryDB -> Authority ->
                IO ()
addDirectory ns logMsg (DDB dirsMV) auth =
  do dirs <- takeMVar dirsMV
     case find matchesFingerprint dirs of
       Just _  -> putMVar dirsMV dirs
       Nothing ->
         do e <- fetch ns (authAddress auth) (authDirPort auth) KeyCertificate
            case e of
              Left _ ->
                do logMsg ("Failed to add new directory for " ++ authName auth)
                   putMVar dirsMV dirs
              Right i ->
                do let newdir = Directory {
                         dirNickname = authName auth
                       , dirIsBridge = False
                       , dirAddress = authAddress auth
                       , dirOnionPort = authOnionPort auth
                       , dirDirPort = authDirPort auth
                       , dirV3Ident = Just (dcFingerprint i)
                       , dirFingerprint = authIdent auth
                       , dirPublished = dcPublished i
                       , dirExpires = dcExpires i
                       , dirIdentityKey = dcIdentityKey i
                       , dirSigningKey = dcSigningKey i
                       }
                   putMVar dirsMV (newdir : dirs)
                   logMsg ("Added new directory entry for " ++ authName auth)
 where
  matchesFingerprint dir =
   case dirV3Ident dir of
    Nothing -> False
    Just x  -> x == authIdent auth
