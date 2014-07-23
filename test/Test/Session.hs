module Test.Session(sessionTests) where

import Control.Applicative
import qualified Data.ByteString.Lazy as BS
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Session

instance Arbitrary Session where
  arbitrary = do l <- choose (0, 32)
                 if l == 0
                    then return EmptySession
                    else Session . BS.pack <$> vector l


prop_SessionSerializes :: Session -> Bool
prop_SessionSerializes = serialProp getSession putSession

sessionTests :: Test
sessionTests =
  testGroup "Session tests" [
    testProperty "Session serializes" prop_SessionSerializes
  ]
