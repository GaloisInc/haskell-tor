{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module TLS.Handshake.CertificateVerify(
         CertificateVerify(..)
       , putCertificateVerify
       , getCertificateVerify
       , generateCertVerify
       )
 where

import Codec.Crypto.RSA.Exceptions
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.X509
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.SignatureAlgorithm
import TLS.Handshake.Type

data CertificateVerify = CertificateVerify {
       cvSignatureAlgorithm :: SignatureAlgorithm
     , cvHashAlgorithm      :: HashAlgorithm
     , cvSignature          :: ByteString
     }
 deriving (Eq, Show)

instance IsHandshake CertificateVerify () where
  handshakeType _ = TypeCertificateVerify
  putHandshake    = putCertificateVerify
  getHandshake _  = getCertificateVerify

putCertificateVerify :: CertificateVerify -> Put
putCertificateVerify cv =
  do putHashAlgorithm      (cvHashAlgorithm cv)
     putSignatureAlgorithm (cvSignatureAlgorithm cv)
     unless (BS.length (cvSignature cv) <= 65535) $
       fail "Signature for CertificateVerify too long."
     putWord16be (fromIntegral (BS.length (cvSignature cv)))
     putLazyByteString (cvSignature cv)

getCertificateVerify :: Get CertificateVerify
getCertificateVerify =
  do cvHashAlgorithm <- getHashAlgorithm
     cvSignatureAlgorithm <- getSignatureAlgorithm
     bslen <- getWord16be
     cvSignature <- getLazyByteString (fromIntegral bslen)
     return CertificateVerify{..}

-- ----------------------------------------------------------------------------

generateCertVerify :: SignatureAlgorithm -> HashAlgorithm ->
                      PrivKey -> ByteString ->
                      CertificateVerify
generateCertVerify siga hasha privkey msg =
  case (siga, privkey) of
    (SigRSA, PrivKeyRSA key) ->
      let hashInfo = hashAlgToHashInfo hasha
          sig = rsassa_pkcs1_v1_5_sign hashInfo key msg
      in CertificateVerify siga hasha sig
    (SigDSA, PrivKeyDSA _key) ->
      error "generateCertVerify"
    _ ->
      error "Unsupported or non-matching signature algorithms."
