module TLS.CipherSuite.HMAC(
         hmac
       , hmac_md5
       , hmac_sha1
       , hmac_sha224
       , hmac_sha256
       , hmac_sha384
       , hmac_sha512
       , generateMACInput
       )
 where

import Data.Binary
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.MD5 hiding (hash)
import Data.Digest.Pure.SHA
import TLS.ProtocolVersion
import TLS.Records.ContentType

hmac :: (ByteString -> ByteString) -> ByteString -> ByteString -> ByteString
hmac h baseK m = h ((k `xorBS` opad) `plus` h ((k `xorBS` ipad) `plus` m))
 where
  k | BS.length baseK == len = baseK
    | BS.length baseK >  len = BS.take len (h baseK `plus` BS.repeat 0)
    | otherwise              = BS.take len (baseK `plus` BS.repeat 0)
  opad      = BS.take len (BS.repeat 0x5c)
  ipad      = BS.take len (BS.repeat 0x36)
  xorBS a b = BS.pack (BS.zipWith xor a b)
  len       = 64 -- see RFC2104
  plus      = BS.append

hmac_md5 :: ByteString -> ByteString -> ByteString
hmac_md5 = hmac (encode . md5)

hmac_sha1 :: ByteString -> ByteString -> ByteString
hmac_sha1 = hmac (bytestringDigest . sha1)

hmac_sha224 :: ByteString -> ByteString -> ByteString
hmac_sha224 = hmac (bytestringDigest . sha224)

hmac_sha256 :: ByteString -> ByteString -> ByteString
hmac_sha256 = hmac (bytestringDigest . sha256)

hmac_sha384 :: ByteString -> ByteString -> ByteString
hmac_sha384 = hmac (bytestringDigest . sha384)

hmac_sha512 :: ByteString -> ByteString -> ByteString
hmac_sha512 = hmac (bytestringDigest . sha512)

generateMACInput :: Word64 -> ContentType -> ProtocolVersion -> ByteString ->
                    ByteString
generateMACInput seqNum cType pv msg =
  runPut $ do putWord64be        seqNum
              putContentType     cType
              putProtocolVersion pv
              putWord16be        (fromIntegral (BS.length msg))
              putLazyByteString  msg
