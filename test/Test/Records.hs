module Test.Records(recordsTests) where

import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Records.ContentType

instance Arbitrary ContentType where
  arbitrary = elements [TypeChangeCipherSpec, TypeAlert,
                        TypeHandshake, TypeApplicationData]

-- ----------------------------------------------------------------------------

prop_ContentTypeSerializes :: ContentType -> Bool
prop_ContentTypeSerializes = serialProp getContentType putContentType

recordsTests :: Test
recordsTests =
  testGroup "Records system tests" [
    testProperty "ContentType serializes" prop_ContentTypeSerializes
  ]
