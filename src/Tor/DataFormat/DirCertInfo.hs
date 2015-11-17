{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
-- |Data formats for directory cert information.
module Tor.DataFormat.DirCertInfo(
         DirectoryCertInfo(..)
       , parseDirectoryCertInfo
       )
 where

import Control.Monad
import Crypto.Hash.Easy
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Data.Attoparsec.ByteString
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.Hourglass
import Tor.DataFormat.Helpers

-- |Information about a directory cert.
data DirectoryCertInfo = DirectoryCertInfo {
       dcFingerprint      :: ByteString
     , dcPublished        :: DateTime
     , dcExpires          :: DateTime
     , dcIdentityKey      :: PublicKey
     , dcSigningKey       :: PublicKey
     , dcKeyCertification :: ByteString
     }
 deriving (Show)

-- FIXME: Handle partial input
-- |Parse in a DirectoryCertInfo.
parseDirectoryCertInfo :: ByteString -> Either String DirectoryCertInfo
parseDirectoryCertInfo bstr =
  case parse dirCertInfo bstr of
    Fail bstr' _ err -> Left (err ++ "[" ++ show (BS.take 10 bstr') ++ "]")
    Partial _        -> Left "Incomplete Directory cert info."
    Done _       res ->
      if verify noHash (dcIdentityKey res) digest (dcKeyCertification res)
         then Right res
         else Left "RSA verification failed."
 where
  digest = generateHash bstr

generateHash :: ByteString -> ByteString
generateHash infile = sha1 (run infile)
 where
  run bstr =
    case BS.span (/= 10) bstr of
      (start, finale) | "\ndir-key-certification\n" `BS.isPrefixOf` finale ->
        start `BS.append` "\ndir-key-certification\n"
      (start, rest) ->
        start `BS.append` (BS.singleton 10) `BS.append` run (BS.drop 1 rest)

dirCertInfo :: Parser DirectoryCertInfo
dirCertInfo =
  do _                       <- string "dir-key-certificate-version 3\n"
     dcFingerprint           <- standardLine "fingerprint" hexDigest
     dcPublished             <- standardLine "dir-key-published" utcTime
     dcExpires               <- standardLine "dir-key-expires" utcTime
     _                       <- string "dir-identity-key\n"
     (dcIdentityKey, idbstr) <- publicKey'
     _                       <- string "dir-signing-key\n"
     dcSigningKey            <- publicKey
     _                       <- string "dir-key-crosscert\n"
     idsig                   <- signature
     _                       <- string "dir-key-certification\n"
     dcKeyCertification      <- signature
     unless (verify noHash dcSigningKey (sha1 idbstr) idsig) $
       fail "RSA ID key verification failed."
     return DirectoryCertInfo{..}

signature :: Parser ByteString
signature =
  do _ <- string "-----BEGIN "
     _ <- option undefined $ string "ID "
     _ <- string "SIGNATURE-----\n"
     let end = string "-----END "
     bstr <- decodeBase64 =<< manyTill base64Char end
     _ <- option undefined $ string "ID "
     _ <- string "SIGNATURE-----\n"
     return bstr
