{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |24-bit words, for use with TLS
module Data.Word24(
         Word24
       , putWord24, getWord24
       )
 where

import Control.Applicative
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.Word

-- |24-bit words.
newtype Word24 = W24 Word32
 deriving (Bits, Eq, Integral, Num, Ord, Real)

instance FiniteBits Word24 where
  finiteBitSize _ = 24

instance Bounded Word24 where
  minBound = W24 0
  maxBound = W24 16777215

instance Enum Word24 where
  succ (W24 16777215) = error "Word24 too big!"
  succ (W24 x)        = W24 (x + 1)
  pred (W24 0)        = error "Word24 too small!"
  pred (W24 x)        = W24 (x - 1)
  toEnum x
    | x < 0           = error "toEnum: value too small for Word24!"
    | x > 16777215    = error "toEnum: value too big for Word24!"
    | otherwise       = W24 (fromIntegral x)
  fromEnum (W24 x)    = fromIntegral x

instance Read Word24 where
  readsPrec a b = map (\ (x,y) -> (W24 x, y)) (readsPrec a b)

instance Show Word24 where
  show (W24 x) = show x

-- |Encode a Word24. Word24s are always synthesized big-endian.
putWord24 :: Word24 -> Put
putWord24 (W24 x) =
  do putWord8 (fromIntegral ((x `shiftR` 16) .&. 0xff))
     putWord8 (fromIntegral ((x `shiftR`  8) .&. 0xff))
     putWord8 (fromIntegral ( x              .&. 0xff))

-- |Decode a Word24. Assumes a big-endian encoding.
getWord24 :: Get Word24
getWord24 =
  do a <- fromIntegral <$> getWord8
     b <- fromIntegral <$> getWord8
     c <- fromIntegral <$> getWord8
     return (W24 ((a `shiftL` 16) + (b `shiftL` 8) + c))
