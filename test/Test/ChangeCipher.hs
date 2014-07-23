module Test.ChangeCipher(changeCipherTests) where

import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.ChangeCipher

instance Arbitrary ChangeCipherSpec where
  arbitrary = return ChangeCipherSpec

-- ----------------------------------------------------------------------------

prop_ChangeCiphSerials :: ChangeCipherSpec -> Bool
prop_ChangeCiphSerials = serialProp getChangeCipherSpec putChangeCipherSpec

changeCipherTests :: Test
changeCipherTests = testProperty "ChangeCipherSpec serializes"
                                 prop_ChangeCiphSerials

