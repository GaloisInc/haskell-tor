{-# LANGUAGE MultiParamTypeClasses #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Codec.Compression.Zlib.OutputWindow(
         OutputWindow
       , emptyWindow
       , addByte
       , addChunk
       , addOldChunk
       , outByteString
       )
 where

import Data.ByteString.Builder
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString as SBS
import qualified Data.ByteString.Lazy as BS
import Data.Int
import Data.FingerTree
import Data.Foldable(foldMap)
import Data.Monoid
import Data.Word

data OutputWindow = OutputWindow {
       owCommitted :: FingerTree Int SBS.ByteString
     , owRecent    :: Builder
     }

instance Monoid Int where
  mempty  = 0
  mappend = (+)

instance Measured Int SBS.ByteString where
  measure = SBS.length

emptyWindow :: OutputWindow
emptyWindow = OutputWindow empty mempty

addByte :: OutputWindow -> Word8 -> OutputWindow
addByte ow b = ow{ owRecent = owRecent ow <> word8 b }

addChunk :: OutputWindow -> ByteString -> OutputWindow
addChunk ow bs = ow{ owRecent = owRecent ow <> lazyByteString bs }

addOldChunk :: OutputWindow -> Int -> Int64 -> (OutputWindow, ByteString)
addOldChunk ow dist len = (OutputWindow output (lazyByteString chunk), chunk)
 where
  output      = owCommitted ow |> BS.toStrict (toLazyByteString (owRecent ow))
  dropAmt     = measure output - dist
  (prev, sme) = split (> dropAmt) output
  s :< rest   = viewl sme
  start       = SBS.take (fromIntegral len) (SBS.drop (dropAmt-measure prev) s)
  len'        = fromIntegral len - SBS.length start
  (m, rest')  = split (> len') rest
  middle      = BS.toStrict (toLazyByteString (outFinger m))
  end         = case viewl rest' of
                  EmptyL -> SBS.empty
                  bs2 :< _ -> SBS.take (len' - measure m) bs2
  chunkInf    = BS.fromChunks [start, middle, end] `BS.append` chunk
  chunk       = BS.take len chunkInf

outFinger :: FingerTree Int SBS.ByteString -> Builder
outFinger = foldMap byteString

outByteString :: OutputWindow -> ByteString
outByteString ow = 
  toLazyByteString (outFinger (owCommitted ow) <> owRecent ow)


