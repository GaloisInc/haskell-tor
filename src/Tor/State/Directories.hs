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
                        IO DirectoryDB
newDirectoryDatabase ns logMsg =
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

-- This is pretty much a copy and paste from the Tor reference source code, and
-- should remain that way in order to make updating it as simple as possible.
defaultStrs :: [String]
defaultStrs = [
  "moria1 orport=9101 " ++
    "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 " ++
    "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
  "tor26 orport=443 " ++
    "v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 " ++
    "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
  "dizum orport=443 " ++
    "v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 " ++
    "194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
  "Tonga orport=443 bridge " ++
    "82.94.251.203:80 4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
  "gabelmoo orport=443 " ++
    "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 " ++
    "131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
  "dannenberg orport=443 " ++
    "v3ident=585769C78764D58426B8B52B6651A5A71137189A " ++
    "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
--  "urras orport=80 " ++
--    "v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C " ++
--    "208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
--  "maatuska orport=80 " ++
--    "v3ident=49015F787433103580E3B66A1707A00E60F2D15B " ++
--    "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
  "Faravahar orport=443 " ++
    "v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 " ++
    "154.35.175.225:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC",
  "longclaw orport=443 " ++
    "v3ident=23D15D965BC35114467363C165C4F724B64B4F66 " ++
    "199.254.238.52:80 74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145"
  ]
