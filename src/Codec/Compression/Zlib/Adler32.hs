module Codec.Compression.Zlib.Adler32(
         AdlerState
       , initialAdlerState
       , advanceAdler
       , finalizeAdler
       )
 where

import Data.Bits
import Data.Word

data AdlerState = AdlerState { adlerA :: !Word16, adlerB :: !Word16 }

initialAdlerState :: AdlerState
initialAdlerState = AdlerState 1 0

adlerAdd :: (Integral a, Integral b) => a -> b -> Word16
adlerAdd x y = fromIntegral ((x32 + y32) `mod` 65521)
 where
  x32, y32 :: Word32
  x32 = fromIntegral x
  y32 = fromIntegral y

advanceAdler :: AdlerState -> Word8 -> AdlerState
advanceAdler state b = AdlerState a' b'
 where
  a' = adlerAdd (adlerA state) b
  b' = adlerAdd (adlerB state) a'

finalizeAdler :: AdlerState -> Word32
finalizeAdler state = ((fromIntegral (adlerB state)) `shiftL` 16)
                   .|.  fromIntegral (adlerA state)


