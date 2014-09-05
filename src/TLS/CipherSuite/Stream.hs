{-# LANGUAGE RecordWildCards  #-}
module TLS.CipherSuite.Stream(
         TLSStreamCipher(..)
       , StreamEncryptor
       , buildStreamEncryptor
       )
 where

import Crypto.Random
import Data.Binary
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Int
import TLS.CipherSuite.Encryptor
import TLS.CipherSuite.HMAC
import TLS.ProtocolVersion
import TLS.Records.ContentType

class TLSStreamCipher k where
  buildStreamKey :: ByteString -> k
  encryptStream  :: k -> ByteString -> ByteString
  decryptStream  :: k -> ByteString -> ByteString

data StreamEncryptor k = StreamEncryptor {
       myMACKey        :: ByteString
     , theirMACKey     :: ByteString
     , myWriteKey      :: k
     , theirWriteKey   :: k
     , lengthMAC       :: Int64
     , cipherHMAC      :: ByteString -> ByteString -> ByteString
     }

instance TLSStreamCipher k => TLSEncryption (StreamEncryptor k) where
  encrypt = streamEncrypt
  decrypt = streamDecrypt

streamEncrypt :: (CryptoRandomGen g, TLSStreamCipher k) =>
                 StreamEncryptor k -> g ->
                 Word64 -> ContentType -> ProtocolVersion -> ByteString ->
                 Either TLSEncryptionError (ByteString, StreamEncryptor k, g)
streamEncrypt enc g seqNum ct pv msg = Right (emsg, enc, g)
 where
  macContents = generateMACInput seqNum ct pv msg
  mac         = cipherHMAC enc (myMACKey enc) macContents
  msg'        = msg `BS.append` mac
  emsg        = encryptStream (myWriteKey enc) msg'

streamDecrypt :: TLSStreamCipher k =>
                 StreamEncryptor k ->
                 Word64 -> ContentType -> ProtocolVersion -> ByteString ->
                 Either TLSEncryptionError (ByteString, StreamEncryptor k)
streamDecrypt enc seqNum ct pv msg
  | msgMAC /= computeMAC = Left MACCodingError
  | otherwise            = Right (content, enc)
 where
  decmsg            = decryptStream (theirWriteKey enc) msg
  contentLen        = fromIntegral (BS.length decmsg) - lengthMAC enc
  (content, msgMAC) = BS.splitAt contentLen decmsg
  macContents       = generateMACInput seqNum ct pv content
  computeMAC        = cipherHMAC enc (theirMACKey enc) macContents

buildStreamEncryptor :: TLSStreamCipher k =>
                        (ByteString -> ByteString) ->
                        k ->
                        ByteString -> ByteString ->
                        ByteString -> ByteString ->
                        ByteString -> ByteString ->
                        Encryptor
buildStreamEncryptor hashfun fake myMACKey theirMACKey mWrite tWrite _ _=
  Encryptor StreamEncryptor{..}
 where
  lengthMAC   = BS.length (hashfun BS.empty)
  cipherHMAC  = hmac hashfun
  (myWriteKey, theirWriteKey) = convert fake (buildStreamKey mWrite) (buildStreamKey tWrite)
  --
  convert :: TLSStreamCipher k => k -> k -> k -> (k, k)
  convert _ a b = (a, b)

