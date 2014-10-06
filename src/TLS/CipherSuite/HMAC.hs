module TLS.CipherSuite.HMAC(
         generateMACInput
       )
 where

import Data.Binary
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import TLS.ProtocolVersion
import TLS.Records.ContentType

generateMACInput :: Word64 -> ContentType -> ProtocolVersion -> ByteString ->
                    ByteString
generateMACInput seqNum cType pv msg =
  runPut $ do putWord64be        seqNum
              putContentType     cType
              putProtocolVersion pv
              putWord16be        (fromIntegral (BS.length msg))
              putLazyByteString  msg
