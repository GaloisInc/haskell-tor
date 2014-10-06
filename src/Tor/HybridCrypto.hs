module Tor.HybridCrypto(
         hybridEncrypt
       , hybridDecrypt
       )
 where

import Codec.Crypto.RSA
import Crypto.Cipher.AES128
import Crypto.Random
import Crypto.Types
import Crypto.Types.PubKey.RSA
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString as BSS
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA

hybridEncrypt :: CryptoRandomGen g =>
                 Bool -> PublicKey -> ByteString -> g ->
                 (ByteString, g)
hybridEncrypt force pubKey m g
  | not force && (BS.length m < (128 - 42)) = -- PK_ENC_LEN - PK_PAD_LEN
     encryptOAEP g sha1 (generateMGF1 sha1) BS.empty pubKey m
  | otherwise =
         -- Generate a KEY_LEN byte random key K;
     let (k, g') = throwLeft (genBytes 16 g)
         -- let M1 = the first PK_ENC_LEN - PK_PAD_LEN - KEY_LEN bytes of M
         -- and let M2 = the rest of M.
         (m1, m2) = BS.splitAt (128 - 42 - 16) m
         -- pad and encrypt K|M1 with PK
         (ekm1, g'') = encryptOAEP g' sha1 (generateMGF1 sha1) BS.empty pubKey
                                   (BS.fromStrict k `BS.append` m1)
         -- encrypt M2 with our stream cipher, using the key K
         Just key = buildKey k :: Maybe AESKey128
         (em2, _) = ctrLazy key (IV (BSS.replicate 16 0))  m2
      in (ekm1 `BS.append` em2, g'')

hybridDecrypt :: PrivateKey -> ByteString -> ByteString
hybridDecrypt privKey em
  | BS.length em <= fromIntegral (private_size privKey) =
      decryptOAEP sha1 (generateMGF1 sha1) BS.empty privKey em
  | otherwise =
     let (ekm1, em2) = BS.splitAt (fromIntegral (private_size privKey)) em
         km1 = decryptOAEP sha1 (generateMGF1 sha1) BS.empty privKey ekm1
         (k, m1) = BS.splitAt 16 km1
         Just key = buildKey (BS.toStrict k) :: Maybe AESKey128
         (m2, _) = unCtrLazy key (IV (BSS.replicate 16 0)) em2
     in m1 `BS.append` m2
