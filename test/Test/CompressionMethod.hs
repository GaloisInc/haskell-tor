module Test.CompressionMethod(compressionMethodTests) where

import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.CompressionMethod

instance Arbitrary CompressionMethod where
  arbitrary = elements rfc5246CompressionMethods

-- ----------------------------------------------------------------------------

prop_CompMethodSerial :: CompressionMethod -> Bool
prop_CompMethodSerial =
  serialProp (getCompressionMethod rfc5246CompressionMethods)
             putCompressionMethod

compressionMethodTests :: Test
compressionMethodTests =
  testGroup "Compression method tests" [
    testProperty "CompressionMethod serializes" prop_CompMethodSerial
  ]
