module Test.Standard where

import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteArray(pack)
import Data.ByteString(ByteString)
import qualified Data.ByteString.Lazy as BS
import Test.QuickCheck

arbitraryRNG :: Gen ChaChaDRG
arbitraryRNG = drgNew

arbitraryBS :: Int -> Gen ByteString
arbitraryBS x = pack <$> replicateM x arbitrary

serialProp :: Eq a => Get a -> (a -> Put) -> a -> Bool
serialProp getter putter x =
  let bstr = runPut (putter x)
      y    = runGet getter bstr
  in x == y

instance MonadRandom Gen where
  getRandomBytes x = pack <$> replicateM x arbitrary
