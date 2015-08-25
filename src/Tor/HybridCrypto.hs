module Tor.HybridCrypto(
         hybridEncrypt
       , hybridDecrypt
       )
 where

import Control.Exception
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash.Algorithms
import Crypto.PubKey.MaskGenFunction
import Crypto.PubKey.RSA.OAEP
import Crypto.PubKey.RSA.Types
import Crypto.Random
import Data.ByteString
import Prelude hiding (append, length, splitAt)

hybridEncrypt :: MonadRandom m =>
                 Bool -> PublicKey -> ByteString ->
                 m ByteString
hybridEncrypt force pubkey m
  | not force && (length m < (128 - 42)) = -- PK_ENC_LEN - PK_PAD_LEN
      failLeft (encrypt oaepParams pubkey m)
  | otherwise =
      do -- Generate a KEY_LEN byte random key K;
         kbs <- getRandomBytes 16
         -- let M1 = the first PK_ENC_LEN - PK_PAD_LEN - KEY_LEN bytes of M
         -- and let M2 = the rest of M.
         let (m1, m2) = splitAt (128 - 42 - 16) m
         -- pad and encrypt K|M1 with PK
         ekm1 <- failLeft (encrypt oaepParams pubkey (kbs `append` m1))
         -- encrypt M2 with our stream cipher, using the key K
         let key = throwCryptoError (cipherInit kbs) :: AES128
             em2 = ctrCombine key nullIV m2
         return (ekm1 `append` em2)

hybridDecrypt :: MonadRandom m =>
                 PrivateKey -> ByteString ->
                 m ByteString
hybridDecrypt privKey em
  | length em <= fromIntegral (private_size privKey) =
      failLeft (decryptSafer oaepParams privKey em)
  | otherwise =
      do let (ekm1, em2) = splitAt (fromIntegral (private_size privKey)) em
         km1 <- failLeft (decryptSafer oaepParams privKey ekm1)
         let (kbs, m1) = splitAt 16 km1
             key       = throwCryptoError (cipherInit kbs) :: AES128
             m2        = ctrCombine key nullIV em2
         return (m1 `append` m2)

oaepParams :: OAEPParams SHA1 ByteString ByteString
oaepParams = OAEPParams SHA1 (mgf1 SHA1) Nothing

failLeft :: (Show a, Monad m) => m (Either a b) -> m b
failLeft action =
  do v <- action
     case v of
       Left err ->
         fail ("Received unexpected left value (HybridCrypto): " ++ show err)
       Right v  -> return v
