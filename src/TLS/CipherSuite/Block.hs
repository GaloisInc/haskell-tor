{-# LANGUAGE RecordWildCards  #-}
module TLS.CipherSuite.Block(
         BlockEncryptor
       , buildBlockEncryptor
       )
 where

import Crypto.Classes
import Crypto.Random
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Int
import Data.Tagged
import Data.Word
import TLS.CipherSuite.Encryptor
import TLS.CipherSuite.HMAC
import TLS.ProtocolVersion
import TLS.Records.ContentType

data BlockEncryptor k = BlockEncryptor {
       myMACKey        :: ByteString
     , theirMACKey     :: ByteString
     , myWriteKey      :: k
     , theirWriteKey   :: k
     , cipherBlockSize :: Int
     , lengthMAC       :: Int64
     , getPadding      :: Int64 -> ByteString
     , cipherHMAC      :: ByteString -> ByteString -> ByteString
     }

instance BlockCipher k => TLSEncryption (BlockEncryptor k) where
  encrypt = blockEncrypt
  decrypt = blockDecrypt

blockEncrypt :: (CryptoRandomGen g, BlockCipher k) =>
                BlockEncryptor k -> g ->
                Word64 -> ContentType -> ProtocolVersion -> ByteString ->
                Either TLSEncryptionError (ByteString, BlockEncryptor k, g)
blockEncrypt enc g seqnum ct pv msg =
  case genBytes (cipherBlockSize enc) g of
    Left err -> Left (RandomGenError err)
    Right (iv, g') ->
      let pad         = getPadding enc (BS.length msg + lengthMAC enc + 1)
          padLen      = fromIntegral (BS.length pad)
          macContents = generateMACInput seqnum ct pv msg
          mac         = cipherHMAC enc (myMACKey enc) macContents
          msg'        = BS.concat [msg, mac, pad, BS.singleton padLen]
          (encmsg, _) = cbcLazy (myWriteKey enc) (IV iv) msg'
      in Right (BS.fromStrict iv `BS.append` encmsg, enc, g')

blockDecrypt :: BlockCipher k =>
                BlockEncryptor k ->
                Word64 -> ContentType -> ProtocolVersion -> ByteString ->
                Either TLSEncryptionError (ByteString, BlockEncryptor k)
blockDecrypt enc seqnum ct pv msg
  | BS.any (/= paddingLen) padding = Left PaddingError
  | mac /= mac'                    = Left MACCodingError
  | otherwise                      = Right (content, enc)
 where
  (iv, encblock)  = BS.splitAt (fromIntegral (cipherBlockSize enc)) msg
  (block, _)      = unCbcLazy (theirWriteKey enc) (IV (BS.toStrict iv)) encblock
  (content, rest) = BS.splitAt (BS.length block - nonContentSize) block
  (mac, padding)  = BS.splitAt (fromIntegral (lengthMAC enc)) rest
  paddingLen      = BS.last block
  nonContentSize  = fromIntegral (lengthMAC enc) + fromIntegral paddingLen + 1
  macContents     = generateMACInput seqnum ct pv content
  mac'            = cipherHMAC enc (theirMACKey enc) macContents

buildBlockEncryptor :: BlockCipher k =>
                       (ByteString -> ByteString) -> k ->
                       ByteString -> ByteString ->
                       ByteString -> ByteString ->
                       ByteString -> ByteString ->
                       Encryptor
buildBlockEncryptor hashfun fake myMACKey theirMACKey mWrite tWrite _ _ =
    Encryptor BlockEncryptor{..}
 where
  cipherBlockSize = getBlockSize myWriteKey blockSizeBytes
  lengthMAC       = BS.length (hashfun BS.empty)
  getPadding      = computePadding (fromIntegral cipherBlockSize)
  cipherHMAC      = hmac hashfun
  (myWriteKey, theirWriteKey) = convert fake (build mWrite) (build tWrite)
  --
  getBlockSize :: BlockCipher k => k -> Tagged k ByteLength -> Int
  getBlockSize _ t = fromIntegral (unTagged t)
  --
  build = buildKey . BS.toStrict
  convert :: BlockCipher k => k -> Maybe k -> Maybe k -> (k, k)
  convert _ (Just a) (Just b) = (a, b)
  convert _ _        _        = error "Bad key decode."

computePadding :: Int64 -> Int64 -> ByteString
computePadding rndAmt current = BS.pack (replicate padAmt (fromIntegral padAmt))
 where
  padAmt = fromIntegral (rndAmt - (current `mod` rndAmt))
