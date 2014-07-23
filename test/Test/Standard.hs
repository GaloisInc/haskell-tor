module Test.Standard where

import Control.Applicative
import Control.Monad
import Crypto.Random.DRBG
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString(pack)
import Data.Tagged
import Test.QuickCheck

arbitraryRNG :: Gen HashDRBG
arbitraryRNG =
  do let tagSeedLen = genSeedLength :: Tagged HashDRBG ByteLength
         tagSeedAmt = unTagged tagSeedLen
     bstr <- pack <$> replicateM tagSeedAmt arbitrary
     case newGen bstr of
       Left e  -> fail ("Couldn't generate arbitrary HashDRBG: " ++ show e)
       Right g -> return g

serialProp :: Eq a => Get a -> (a -> Put) -> a -> Bool
serialProp getter putter x =
  let bstr = runPut (putter x)
      y    = runGet getter bstr
  in x == y

 
