{-# LANGUAGE OverloadedStrings #-}
module TLS.Certificate.DistinguishedName(
         DistinguishedName
       , getDistinguishedName
       , putDistinguishedName
       )
 where

import Control.Monad
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString.Lazy as BS
import Data.X509

putDistinguishedName :: DistinguishedName -> Put
putDistinguishedName dn =
  do let asn1 = toASN1 dn []
         bstr = encodeASN1 DER asn1
     unless (BS.length bstr >= 1) $
       fail "DN too short to encode!"
     unless (BS.length bstr <= 65535) $
       fail "DN too long to encode!"
     putWord16be (fromIntegral (BS.length bstr))
     putLazyByteString bstr

getDistinguishedName :: Get DistinguishedName
getDistinguishedName =
  do len <- getWord16be
     bstr <- getLazyByteString (fromIntegral len)
     case decodeASN1 DER bstr of
       Left asn1err -> fail ("ASN1 Decoding error (DN): " ++ show asn1err)
       Right asn1 ->
         case fromASN1 asn1 of
           Left err        -> fail ("DN decoding error: " ++ err)
           Right (res, []) -> return res
           Right (_, _)    -> fail ("Too much data parsing DN!")
