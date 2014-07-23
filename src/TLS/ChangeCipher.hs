module TLS.ChangeCipher(
         ChangeCipherSpec(..)
       , getChangeCipherSpec
       , putChangeCipherSpec
       )
 where

import Control.Monad
import Data.Binary.Put
import Data.Binary.Get

data ChangeCipherSpec = ChangeCipherSpec
 deriving (Eq, Show)

getChangeCipherSpec :: Get ChangeCipherSpec
getChangeCipherSpec =
  do b <- getWord8
     unless (b == 1) $ fail "Improper format for ChangeCipherSpec"
     return ChangeCipherSpec

putChangeCipherSpec :: ChangeCipherSpec -> Put
putChangeCipherSpec _ = putWord8 1
