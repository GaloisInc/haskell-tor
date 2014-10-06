{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.DataFormat.DirCertInfo(
         DirectoryCertInfo(..)
       , parseDirectoryCertInfo
       )
 where

import Codec.Crypto.RSA.Pure
import Data.Attoparsec.ByteString.Lazy
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Time
import Tor.DataFormat.Helpers

data DirectoryCertInfo = DirectoryCertInfo {
       dcFingerprint      :: ByteString
     , dcPublished        :: UTCTime
     , dcExpires          :: UTCTime
     , dcIdentityKey      :: PublicKey
     , dcSigningKey       :: PublicKey
     , dcKeyCertification :: ByteString
     }
 deriving (Show)

parseDirectoryCertInfo :: ByteString -> Either String DirectoryCertInfo
parseDirectoryCertInfo bstr =
  case parse dirCertInfo bstr of
    Fail bstr' _ err -> Left (err ++ "[" ++ show (BS.take 10 bstr') ++ "]")
    Done _       res ->
      let key = dcIdentityKey res
          sig = dcKeyCertification res
      in case rsassa_pkcs1_v1_5_verify hashEmpty key digest sig of
           Left err ->
             Left ("RSA verification failed: " ++ show err)
           Right False ->
             Left ("Invalid signature: " ++ show sig)
           Right True ->
             Right res
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
     let digest = sha1 idbstr
     case rsassa_pkcs1_v1_5_verify hashEmpty dcSigningKey digest idsig of
        Left err ->
          fail ("RSA ID key verification failed: " ++ show err)
        Right False ->
          fail ("RSA ID key verification failure.")
        Right True ->
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


hashEmpty :: HashInfo  
hashEmpty = HashInfo BS.empty id
