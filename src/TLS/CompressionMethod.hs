{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.CompressionMethod(
         -- * Compression method encoding
         CompressionMethod
       , getCompressor
       , getCompressionMethod
       , putCompressionMethod
         -- * Compression method definition and usage
       , TLSCompression(..)
       , Compressor
       , runCompress
       , runDecompress
         -- * Known compression methods
       , nullCompression
       , rfc5246CompressionMethods
       )
 where

import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import Data.List
import Data.Word

class TLSCompression a where
  compress   :: a -> ByteString -> (ByteString, a)
  decompress :: a -> ByteString -> (ByteString, a)

data Compressor = forall c. TLSCompression c => Compressor c

runCompress :: Compressor -> ByteString -> (ByteString, Compressor)
runCompress (Compressor c) bstr = (bstr', Compressor c')
 where
  (bstr', c') = compress c bstr

runDecompress :: Compressor -> ByteString -> (ByteString, Compressor)
runDecompress (Compressor c) bstr = (bstr', Compressor c')
 where
  (bstr', c') = decompress c bstr

-- ----------------------------------------------------------------------------

data CompressionMethod = CompressionMethod {
       compName       :: String
     , compIdentifier :: Word8
     , compCompressor :: Compressor
     }

instance Eq CompressionMethod where
  a == b = compName a == compName b

instance Show CompressionMethod where
  show = compName

getCompressor :: CompressionMethod -> Compressor
getCompressor = compCompressor

-- ----------------------------------------------------------------------------

putCompressionMethod :: CompressionMethod -> Put
putCompressionMethod = putWord8 . compIdentifier

getCompressionMethod :: [CompressionMethod] -> Get CompressionMethod
getCompressionMethod methods =
  do i <- getWord8
     case find (\ x -> i == compIdentifier x) methods of
       Nothing -> fail "Couldn't find matching compression method."
       Just cm -> return cm

-- ----------------------------------------------------------------------------

newtype NullCompressorState = NCS ()

instance TLSCompression NullCompressorState where
  compress   s bstr = (bstr, s)
  decompress s bstr = (bstr, s)

nullCompression :: CompressionMethod
nullCompression = CompressionMethod {
    compName       = "NULL"
  , compIdentifier = 0
  , compCompressor = Compressor (NCS ())
  }

rfc5246CompressionMethods :: [CompressionMethod]
rfc5246CompressionMethods = [nullCompression]

