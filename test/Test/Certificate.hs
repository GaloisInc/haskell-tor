{-# LANGUAGE RecordWildCards #-}
module Test.Certificate(certificateTests) where

import Codec.Crypto.RSA
import Control.Applicative
import Control.Monad
import Crypto.Random
import Crypto.Random.DRBG
import qualified Data.ByteString as BSS
import Data.Digest.Pure.SHA
import Data.Tagged
import Data.Time
import Data.X509
import Test.DistinguishedName()
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Certificate

instance Arbitrary ASN1Cert where
  arbitrary =
    do certVersion      <- arbitrary
       certSerial       <- arbitrary
       certIssuerDN     <- arbitrary
       certSubjectDN    <- arbitrary
       hashAlg          <- elements [HashSHA1, HashSHA256, HashSHA384]

       let tagSeedLen = genSeedLength :: Tagged HashDRBG ByteLength
           tagSeedAmt = unTagged tagSeedLen
       bstr <- BSS.pack <$> replicateM tagSeedAmt arbitrary
       let Right g = newGen bstr :: Either GenError HashDRBG
       let (pub, _, _) = generateKeyPair g 1024

       let keyAlg           = PubKeyALG_RSA -- FIXME?
           certSignatureAlg = SignatureALG hashAlg keyAlg
           certValidity     = (UTCTime (fromGregorian 1978 3 4) 0,
                               UTCTime (fromGregorian 2048 3 4) 0)
           certPubKey       = PubKeyRSA pub
           certExtensions   = Extensions Nothing

       let baseCert = Certificate{ .. }
           sigfun   = case hashAlg of
                        HashSHA1   -> wrapSignatureAlg certSignatureAlg sha1
                        HashSHA224 -> wrapSignatureAlg certSignatureAlg sha224
                        HashSHA256 -> wrapSignatureAlg certSignatureAlg sha256
                        HashSHA384 -> wrapSignatureAlg certSignatureAlg sha384
                        HashSHA512 -> wrapSignatureAlg certSignatureAlg sha512
                        _          -> error "INTERNAL WEIRDNESS"
       let (signedCert, _) = objectToSignedExact sigfun baseCert
       return (ASN1Cert signedCert)

-- ----------------------------------------------------------------------------

prop_ASN1CertSerial :: ASN1Cert -> Bool
prop_ASN1CertSerial = serialProp getASN1Cert putASN1Cert

certificateTests :: Test
certificateTests =
  testProperty "Certificates serialize" prop_ASN1CertSerial
