module Crypto.PubKey.RSA.KeyHash(
         keyHash
       , keyHash'
       )
 where

import Data.ByteString(ByteString)
import Crypto.PubKey.RSA
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.X509

keyHash :: (ByteString -> ByteString) -> Certificate -> ByteString
keyHash hash cert =
 case certPubKey cert of
   PubKeyRSA k -> keyHash' hash k
   _           -> error "Unknown key type in keyHash."

keyHash' :: (ByteString -> ByteString) -> PublicKey -> ByteString
keyHash' hash k = hash (encodeASN1' DER asn1)
 where
  asn1   = [Start Sequence, IntVal n, IntVal e, End Sequence]
  n      = public_n k
  e      = public_e k
