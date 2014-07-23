module Test.Random(randomTests) where

import Control.Applicative
import qualified Data.ByteString.Lazy as BS
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Random

instance Arbitrary Random where
  arbitrary = Random <$> arbitrary <*> (BS.pack <$> vector 28)

prop_RandomSerializes :: Random -> Bool
prop_RandomSerializes = serialProp getRandom putRandom

randomTests :: Test
randomTests =
  testGroup "Random tests" [
    testProperty "Random serializes" prop_RandomSerializes
  ]
