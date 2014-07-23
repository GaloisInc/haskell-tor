{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.Handshake.Certificate(
         Certificate(..)
       , putCertificate
       , getCertificate
       )
 where

import Control.Applicative
import Data.Binary.Get
import Data.Binary.Put
import Data.Binary.TLSVector
import Data.Word24
import TLS.Certificate
import TLS.Handshake.Type

data Certificate = Certificate { 
       cCertificateList :: [ASN1Cert]
     }
 deriving (Eq, Show)

instance IsHandshake Certificate () where
  handshakeType _ = TypeCertificate
  putHandshake    = putCertificate
  getHandshake _  = getCertificate

putCertificate :: Certificate -> Put
putCertificate c =
  putVector 0 16777215 putWord24 putASN1Cert (cCertificateList c)

getCertificate :: Get Certificate
getCertificate =
  Certificate <$> getVector 0 16777215 getWord24 getASN1Cert

