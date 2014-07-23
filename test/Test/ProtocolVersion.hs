module Test.ProtocolVersion(protocolVersionTests) where

import Control.Applicative
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.HUnit hiding (Test)
import Test.QuickCheck
import Test.Standard
import TLS.ProtocolVersion

instance Arbitrary ProtocolVersion where
  arbitrary = ProtocolVersion <$> arbitrary <*> arbitrary

prop_ProtVerSerializes :: ProtocolVersion -> Bool
prop_ProtVerSerializes = serialProp getProtocolVersion putProtocolVersion

-- ----------------------------------------------------------------------------

protocolVersionTests :: Test
protocolVersionTests =
  testGroup "Protocol Version tests" [
    testProperty "ProtocolVersion serializes" prop_ProtVerSerializes
  , testCase "1.0 < 1.1"  $ assertBool "" (versionTLS1_0 <  versionTLS1_1)
  , testCase "1.1 < 1.2"  $ assertBool "" (versionTLS1_1 <  versionTLS1_2)
  , testCase "1.2 > 1.0"  $ assertBool "" (versionTLS1_2 >  versionTLS1_0)
  , testCase "1.2 == 1.2" $ assertBool "" (versionTLS1_2 == versionTLS1_2)
  ]
