{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module TLS.Handshake.CertificateRequest(
         CertificateRequest(..)
       , putCertificateRequest
       , getCertificateRequest
       )
 where

import Control.Applicative
import Data.Binary.Get
import Data.Binary.Put
import Data.Binary.TLSVector
import TLS.Certificate.ClientCertificateType
import TLS.Certificate.DistinguishedName
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.SignatureAlgorithm
import TLS.Handshake.Type
import TLS.ProtocolVersion

data CertificateRequest = CertificateRequest {
       crCertificateTypes             :: [ClientCertificateType]
     , crSupportedSignatureAlgorithms :: Maybe [(SignatureAlgorithm,
                                                 HashAlgorithm)]
     , crCertificateAuthorities       :: [DistinguishedName]
     }
 deriving (Eq, Show)

instance IsHandshake CertificateRequest ProtocolVersion where
  handshakeType _ = TypeCertificateRequest
  putHandshake    = putCertificateRequest
  getHandshake    = getCertificateRequest

putCertificateRequest :: CertificateRequest -> Put
putCertificateRequest x =
  do putVector 1 255 putWord8 putClientCertificateType (crCertificateTypes x)
     case (crSupportedSignatureAlgorithms x) of
       Nothing ->
         return ()
       Just sigalgs ->
         putVector 0 65535 putWord16be putSigHash sigalgs
     putVector 0 65535 putWord16be putDistinguishedName
               (crCertificateAuthorities x)
 where
  putSigHash (sig, hash) =
    do putHashAlgorithm hash
       putSignatureAlgorithm sig

getCertificateRequest :: ProtocolVersion -> Get CertificateRequest
getCertificateRequest v =
  do crCertificateTypes <- getVector 1 255 getWord8 getClientCertificateType
     crSupportedSignatureAlgorithms <-
       if (v < versionTLS1_2)
         then return Nothing
         else Just <$> getVector 0 65535 getWord16be getSigHash
     crCertificateAuthorities <- getVector 0 65535 getWord16be
                                           getDistinguishedName
     return CertificateRequest{..}
 where
   getSigHash =
     do hash <- getHashAlgorithm
        sig <- getSignatureAlgorithm
        return (sig, hash)
