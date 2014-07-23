module TLS.CipherSuite.HashAlgorithm(
         HashAlgorithm(..)
       , putHashAlgorithm
       , getHashAlgorithm
       , hashAlgToHashInfo
       , hashAlgorithmLength
       )
 where

import Codec.Crypto.RSA.Pure
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString.Lazy as BS
import Data.Int

data HashAlgorithm = HashNone   | HashMD5    | HashSHA1   | HashSHA224
                   | HashSHA256 | HashSHA384 | HashSHA512
 deriving (Eq, Show)

putHashAlgorithm :: HashAlgorithm -> Put
putHashAlgorithm HashNone   = putWord8 0
putHashAlgorithm HashMD5    = putWord8 1
putHashAlgorithm HashSHA1   = putWord8 2
putHashAlgorithm HashSHA224 = putWord8 3
putHashAlgorithm HashSHA256 = putWord8 4
putHashAlgorithm HashSHA384 = putWord8 5
putHashAlgorithm HashSHA512 = putWord8 6

getHashAlgorithm :: Get HashAlgorithm
getHashAlgorithm =
  do b <- getWord8
     case b of
       0 -> return HashNone
       1 -> return HashMD5
       2 -> return HashSHA1
       3 -> return HashSHA224
       4 -> return HashSHA256
       5 -> return HashSHA384
       6 -> return HashSHA512
       _ -> fail "Invalid value for HashAlgorithm."

-- ----------------------------------------------------------------------------

hashAlgToHashInfo :: HashAlgorithm -> HashInfo
hashAlgToHashInfo HashNone   = HashInfo BS.empty (const BS.empty)
hashAlgToHashInfo HashMD5    = hashMD5
hashAlgToHashInfo HashSHA1   = hashSHA1
hashAlgToHashInfo HashSHA224 = hashSHA224
hashAlgToHashInfo HashSHA256 = hashSHA256
hashAlgToHashInfo HashSHA384 = hashSHA384
hashAlgToHashInfo HashSHA512 = hashSHA512

hashAlgorithmLength :: HashAlgorithm -> Int64
hashAlgorithmLength HashNone   = 0
hashAlgorithmLength HashMD5    = 128 `div` 8
hashAlgorithmLength HashSHA1   = 160 `div` 8
hashAlgorithmLength HashSHA224 = 224 `div` 8
hashAlgorithmLength HashSHA256 = 256 `div` 8
hashAlgorithmLength HashSHA384 = 384 `div` 8
hashAlgorithmLength HashSHA512 = 512 `div` 8
