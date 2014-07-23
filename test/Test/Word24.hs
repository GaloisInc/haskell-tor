module Test.Word24(word24Tests) where

import Data.Word24
import Test.QuickCheck(Arbitrary(..), choose)
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.Standard

instance Arbitrary Word24 where
  arbitrary = toEnum `fmap` choose (0, 16777215)

prop_Word24Serializes :: Word24 -> Bool
prop_Word24Serializes = serialProp getWord24 putWord24

word24Tests :: Test
word24Tests =
  testGroup "Word24 Tests" [
    testProperty "Word24 round-trips" prop_Word24Serializes
  ]
