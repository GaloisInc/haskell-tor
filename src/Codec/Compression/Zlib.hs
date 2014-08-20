{-# LANGUAGE MultiWayIf #-}
module Codec.Compression.Zlib(
         decompress
       )
 where

import Codec.Compression.Zlib.Deflate
import Codec.Compression.Zlib.Monad
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS

decompress :: ByteString -> Maybe ByteString
decompress ifile =
  case BS.uncons ifile of
    Nothing -> error "Could not read CMF."
    Just (cmf, rest) ->
     case BS.uncons rest of
       Nothing -> error "Could not read FLG."
       Just (_, rest') ->
         let cm         = cmf .&. 0x0F
             cinfo      = cmf `shiftR` 4
         in if| cm    /= 8 -> error "Non-DEFLATE compression method."
              | cinfo >  7 -> error "Window size too big."
              | otherwise  -> runDeflateM inflate rest'
