{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module TLS.Certificate(
         ASN1Cert(..)
       , putASN1Cert
       , getASN1Cert
       , certificatePublicKey
       , generateCertificate
       , getDiffieHellmanGroup
       , getDiffieHellmanPublic
       , getDiffieHellmanPrivate
       , wrapSignatureAlg
       , keyHash, keyHash'
       , certificateHash
       , certExpired
       , isSignedBy
       )
 where

import Codec.Crypto.RSA.Exceptions
import Control.Applicative
import Control.Monad
import Crypto.Random.DRBG
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.OID
import Data.ASN1.Types
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString as BSS
import Data.Digest.Pure.SHA
import Data.Time
import Data.Word24
import Data.X509
import TLS.DiffieHellman

newtype ASN1Cert = ASN1Cert SignedCertificate
 deriving (Eq, Show)

putASN1Cert :: ASN1Cert -> Put
putASN1Cert (ASN1Cert x) =
  do let bstr = encodeSignedObject x
         len  = BSS.length bstr
     unless (len >= 1) $
       fail "ASN.1 cert too small to encode."
     unless (len <= 16777215) $
       fail "ASN.1 cert too large to encode."
     putWord24 (fromIntegral len)
     putByteString bstr

getASN1Cert :: Get ASN1Cert
getASN1Cert =
  do len <- fromIntegral <$> getWord24
     unless (len >= 1) $
       fail "ASN.1 cert length too small."
     unless (len <= 16777215) $
       fail "ASN.1 cert length too large."
     bstr <- getByteString len
     case decodeSignedCertificate bstr of
       Left str -> fail ("Invalid certificate: " ++ str)
       Right sc -> return (ASN1Cert sc)

-- ----------------------------------------------------------------------------

certificatePublicKey :: ASN1Cert -> PubKey
certificatePublicKey (ASN1Cert cert) =
  certPubKey (signedObject (getSigned cert))

getDiffieHellmanGroup :: Monad m => ASN1Cert -> m DiffieHellmanGroup
getDiffieHellmanGroup _ = fail "Certificate-based DH not currently supported."

getDiffieHellmanPublic :: Monad m => ASN1Cert -> m Integer
getDiffieHellmanPublic _ = fail "Certificate-based DH not currently supported."

getDiffieHellmanPrivate :: Monad m => ASN1Cert -> m Integer
getDiffieHellmanPrivate _ = fail "Certificate-based DH not currently supported."

generateCertificate :: CryptoRandomGen g => g -> (ASN1Cert, PrivKey, g)
generateCertificate g = (ASN1Cert signedCert, PrivKeyRSA priv, g')
 where
  (signedCert, _)       = objectToSignedExact wrap_sha256 unsignedCert
  signatureAlg          = SignatureALG HashSHA256 PubKeyALG_RSA
  wrap_sha256           = wrapSignatureAlg signatureAlg sha256
  unsignedCert          = Certificate{ .. }
  (pub, priv, g')       = generateKeyPair g 4096
  certVersion           = 3
  certSerial            = 101
  certIssuerDN          = DistinguishedName [
                            (getObjectID DnCommonName,       "Adam")
                          , (getObjectID DnCountry,          "US")
                          , (getObjectID DnOrganization,     "Galois")
                          , (getObjectID DnOrganizationUnit, "Systems Software")
                          ]
  certSubjectDN         = certIssuerDN
  certSignatureAlg      = SignatureALG HashSHA256 PubKeyALG_RSA
  certValidity          = (UTCTime (fromGregorian 1978 3 4) 0,
                           UTCTime (fromGregorian 2048 3 4) 0)
  certPubKey            = PubKeyRSA pub
  certExtensions        = Extensions Nothing

wrapSignatureAlg :: SignatureALG ->
                    (ByteString -> ByteString) ->
                    BSS.ByteString ->
                    (BSS.ByteString, SignatureALG, ())
wrapSignatureAlg name sha bstr =
  let inbstrL  = BS.fromChunks [bstr]
      hashed   = sha inbstrL
      stricted = BSS.concat (BS.toChunks hashed)
  in (stricted, name, ())

-- ----------------------------------------------------------------------------

keyHash :: (ByteString -> ByteString) -> Certificate -> ByteString
keyHash hash cert =
 case certPubKey cert of
   PubKeyRSA k -> keyHash' hash k
   _           -> error "Unknown key type in keyHash."

keyHash' :: (ByteString -> ByteString) -> PublicKey -> ByteString
keyHash' hash k = hash (encodeASN1 DER asn1)
 where
  asn1   = [Start Sequence, IntVal n, IntVal e, End Sequence]
  n      = public_n k
  e      = public_e k

certificateHash :: (ByteString -> ByteString) -> Certificate -> ByteString
certificateHash hash cert = hash (encodeASN1 DER (toASN1 cert []))

-- ----------------------------------------------------------------------------

certExpired :: Certificate -> UTCTime -> Bool
certExpired cert t = (aft > t) || (t > unt)
 where (aft, unt) = certValidity cert

isSignedBy :: SignedCertificate -> Certificate -> Bool
isSignedBy cert bycert =
  case signedAlg (getSigned cert) of
    SignatureALG_Unknown _             -> False
    SignatureALG HashMD2 PubKeyALG_RSA -> False
    SignatureALG hashAlg PubKeyALG_RSA ->
      case certPubKey bycert of
        PubKeyRSA pubkey ->
          let sig  = BS.fromStrict (signedSignature (getSigned cert))
              bstr = BS.fromStrict (getSignedData cert)
              hash = hashAlgToHashInfo hashAlg
          in rsassa_pkcs1_v1_5_verify hash pubkey bstr sig
        _ -> False
    SignatureALG _ _     -> False
 where
  hashAlgToHashInfo HashMD2    = error "Internal error."
  hashAlgToHashInfo HashMD5    = hashMD5
  hashAlgToHashInfo HashSHA1   = hashSHA1
  hashAlgToHashInfo HashSHA224 = hashSHA224
  hashAlgToHashInfo HashSHA256 = hashSHA256
  hashAlgToHashInfo HashSHA384 = hashSHA384
  hashAlgToHashInfo HashSHA512 = hashSHA512
