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
       )
 where

import Codec.Crypto.RSA.Exceptions
import Control.Applicative
import Control.Monad
import Crypto.Random.DRBG
import Data.ASN1.OID
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
                    (ByteString -> Digest t) ->
                    BSS.ByteString ->
                    (BSS.ByteString, SignatureALG, ())
wrapSignatureAlg name sha bstr =
  let inbstrL  = BS.fromChunks [bstr]
      hashed   = bytestringDigest (sha inbstrL)
      stricted = BSS.concat (BS.toChunks hashed)
  in (stricted, name, ())

