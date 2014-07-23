module Test.HashAlgorithm(hashAlgorithmTests) where

import Codec.Crypto.RSA.Pure
import qualified Data.ByteString.Lazy as BS
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.CipherSuite.HashAlgorithm

instance Arbitrary HashAlgorithm where
  arbitrary = elements [ HashNone, HashMD5, HashSHA1, HashSHA224
                       , HashSHA256, HashSHA384, HashSHA512 ]

-- ----------------------------------------------------------------------------

prop_HashAlgSerializes :: HashAlgorithm -> Bool
prop_HashAlgSerializes = serialProp getHashAlgorithm putHashAlgorithm

prop_HashLengthRight :: HashAlgorithm -> Bool
prop_HashLengthRight alg = hashAlgorithmLength alg == algLength
 where
  algLength  = BS.length hashedNull
  hashedNull = hashFunction (hashAlgToHashInfo alg) BS.empty

hashAlgorithmTests :: Test
hashAlgorithmTests =
  testGroup "Hash Algorithm Tests" [
    testProperty "HashAlgorithm serializes" prop_HashAlgSerializes
  , testProperty "HashAlgorithm lengths are right" prop_HashLengthRight
  ]
