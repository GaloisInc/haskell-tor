module Test.Standard where

import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteArray(pack)
import Data.ByteString(ByteString)
import Prelude()
import Prelude.Compat
import Test.QuickCheck
import Tor.Options

arbitraryRNG :: Gen ChaChaDRG
arbitraryRNG = drgNew

arbitraryBS :: Int -> Gen ByteString
arbitraryBS x = pack <$> vectorOf x arbitrary

instance Arbitrary ByteString where
  arbitrary = sized arbitraryBS

serialProp :: Eq a => Get a -> (a -> Put) -> a -> Bool
serialProp getter putter x =
  let bstr = runPut (putter x)
      y    = runGet getter bstr
  in x == y

instance MonadRandom Gen where
  getRandomBytes x = pack <$> replicateM x arbitrary

testOptions :: TorOptions
testOptions = defaultTorOptions { torLog = const (return ()) }
