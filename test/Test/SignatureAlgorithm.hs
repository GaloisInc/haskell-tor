module Test.SignatureAlgorithm(signatureAlgorithmTests) where

import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.CipherSuite.SignatureAlgorithm


instance Arbitrary SignatureAlgorithm where
  arbitrary = elements [SigAnonymous, SigRSA, SigDSA, SigECDSA]

-- ----------------------------------------------------------------------------

prop_SigAlgSerializes :: SignatureAlgorithm -> Bool
prop_SigAlgSerializes = serialProp getSignatureAlgorithm putSignatureAlgorithm

signatureAlgorithmTests :: Test
signatureAlgorithmTests = testProperty "SignatureAlgorithm serializes."
                                      prop_SigAlgSerializes
