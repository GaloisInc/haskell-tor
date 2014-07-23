{-# LANGUAGE RecordWildCards #-}
module TLS.Random(
         Random(..)
       , getRandom
       , putRandom
       , generateRandom
       )
 where

import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Time
import Data.Word

data Random = Random {
       rndGMTUnixTime :: Word32
     , rndRandomBytes :: ByteString
     }
 deriving (Eq, Show)

putRandom :: Random -> Put
putRandom c =
  do putWord32be (rndGMTUnixTime c)
     putLazyByteString (rndRandomBytes c)
     unless (BS.length (rndRandomBytes c) == 28) $
       fail "Improper number of bytes in Random section."

getRandom :: Get Random
getRandom =
  do rndGMTUnixTime <- getWord32be
     rndRandomBytes <- getLazyByteString 28
     return Random{ .. }

-- ----------------------------------------------------------------------------

generateRandom :: CryptoRandomGen g => g -> IO (Either GenError (Random, g))
generateRandom g =
  do let epoch = fromGregorian 1970 1 1
     now <- getCurrentTime
     let daysFromEpoch = diffDays (utctDay now) epoch
         secsFromEpoch = fromIntegral daysFromEpoch * 24 * 60 * 60
         timeMark      = secsFromEpoch + fromEnum (utctDayTime now)
     case genBytes 28 g of
       Left err         ->
         return (Left err)
       Right (bstr, g') ->
         do let bstr' = BS.fromChunks [bstr]
            return (Right (Random (fromIntegral timeMark) bstr', g'))
