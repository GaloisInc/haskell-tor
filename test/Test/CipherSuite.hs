module Test.CipherSuite(cipherSuiteTests) where

import Data.List
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.HUnit(assertEqual)
import Test.Standard
import TLS.CipherSuite

instance Arbitrary CipherSuite where
  arbitrary = elements rfc5246CipherSuites

prop_CipherSerial :: CipherSuite -> Bool
prop_CipherSerial = serialProp (getCipherSuite rfc5246CipherSuites)
                               putCipherSuite

-- these were copied and reworked by vim rather than manually copied, like
-- the lists above, and so should be a bit more reliable for cross-checking
-- that I typed things in correctly.
cipherSuiteTests :: Test
cipherSuiteTests =
  testGroup "CipherSuite tests" [
    testProperty "CipherSuite serializes" prop_CipherSerial
  , testGroup "CipherSuite ID checks" [
      checkIdentifier 0x00 0x00 "TLS_NULL_WITH_NULL_NULL"
    , checkIdentifier 0x00 0x01 "TLS_RSA_WITH_NULL_MD5"
    , checkIdentifier 0x00 0x02 "TLS_RSA_WITH_NULL_SHA"
    , checkIdentifier 0x00 0x3B "TLS_RSA_WITH_NULL_SHA256"
    , checkIdentifier 0x00 0x04 "TLS_RSA_WITH_RC4_128_MD5"
    , checkIdentifier 0x00 0x05 "TLS_RSA_WITH_RC4_128_SHA"
    , checkIdentifier 0x00 0x0A "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    , checkIdentifier 0x00 0x2F "TLS_RSA_WITH_AES_128_CBC_SHA"
    , checkIdentifier 0x00 0x35 "TLS_RSA_WITH_AES_256_CBC_SHA"
    , checkIdentifier 0x00 0x3C "TLS_RSA_WITH_AES_128_CBC_SHA256"
    , checkIdentifier 0x00 0x3D "TLS_RSA_WITH_AES_256_CBC_SHA256"
    , checkIdentifier 0x00 0x0D "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
    , checkIdentifier 0x00 0x10 "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
    , checkIdentifier 0x00 0x13 "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
    , checkIdentifier 0x00 0x16 "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
    , checkIdentifier 0x00 0x30 "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
    , checkIdentifier 0x00 0x31 "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
    , checkIdentifier 0x00 0x32 "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
    , checkIdentifier 0x00 0x33 "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    , checkIdentifier 0x00 0x36 "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
    , checkIdentifier 0x00 0x37 "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
    , checkIdentifier 0x00 0x38 "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
    , checkIdentifier 0x00 0x39 "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    , checkIdentifier 0x00 0x3E "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
    , checkIdentifier 0x00 0x3F "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
    , checkIdentifier 0x00 0x40 "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
    , checkIdentifier 0x00 0x67 "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
    , checkIdentifier 0x00 0x68 "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
    , checkIdentifier 0x00 0x69 "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
    , checkIdentifier 0x00 0x6A "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
    , checkIdentifier 0x00 0x6B "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    , checkIdentifier 0x00 0x18 "TLS_DH_anon_WITH_RC4_128_MD5"
    , checkIdentifier 0x00 0x1B "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
    , checkIdentifier 0x00 0x34 "TLS_DH_anon_WITH_AES_128_CBC_SHA"
    , checkIdentifier 0x00 0x3A "TLS_DH_anon_WITH_AES_256_CBC_SHA"
    , checkIdentifier 0x00 0x6C "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
    , checkIdentifier 0x00 0x6D "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
    ]
  ]
 where
  checkIdentifier a b str =
    let tname = str ++ " has right ident"
    in testCase tname (assertEqual tname str (getId a b))
  --
  getId a b =
    case find (matchId a b) rfc5246CipherSuites of
      Nothing -> "BAD BAD"
      Just x  -> cipherName x
  --
  matchId a b CipherSuite{ cipherIdentifier = (m, n) } = (a == m) && (n == b)
