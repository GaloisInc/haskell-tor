module TLS.CipherSuite(
         -- * CipherSuite definition
         CipherSuite(..)
       , putCipherSuite
       , getCipherSuite
       , cipherRequiresServerCert
       , cipherVerifyDataLength
       , cipherMACKeyLength
         -- * Types of ciphers
       , CipherType(..)
       , rfc5246CipherSuites
         -- * Cipher Suites defined in RFC 5246
       , suiteTLS_NULL_WITH_NULL_NULL
       , suiteTLS_RSA_WITH_NULL_MD5
       , suiteTLS_RSA_WITH_NULL_SHA
       , suiteTLS_RSA_WITH_NULL_SHA256
       , suiteTLS_RSA_WITH_RC4_128_MD5
       , suiteTLS_RSA_WITH_RC4_128_SHA
       , suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_RSA_WITH_AES_128_CBC_SHA256
       , suiteTLS_RSA_WITH_AES_256_CBC_SHA256
       , suiteTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA
       , suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA
       , suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA256
       , suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA256
       , suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA256
       , suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA256
       , suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA256
       , suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA256
       , suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA256
       , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256
       , suiteTLS_DH_anon_WITH_RC4_128_MD5
       , suiteTLS_DH_anon_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DH_anon_WITH_AES_128_CBC_SHA
       , suiteTLS_DH_anon_WITH_AES_256_CBC_SHA
       , suiteTLS_DH_anon_WITH_AES_128_CBC_SHA256
       , suiteTLS_DH_anon_WITH_AES_256_CBC_SHA256
       )
 where

import Crypto.Cipher.AES128
import Data.Int
import Data.List
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import Data.Digest.Pure.MD5
import Data.Digest.Pure.SHA
import Data.Serialize(encodeLazy)
import Data.Word
import Numeric
import TLS.CipherSuite.Block
import TLS.CipherSuite.Encryptor
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.KeyExchangeAlgorithm
import TLS.CipherSuite.Null
import TLS.CipherSuite.RC4
import TLS.CipherSuite.SignatureAlgorithm
import TLS.CipherSuite.Stream
import TLS.CipherSuite.TripleDES

data CipherSuite = CipherSuite {
    cipherName                 :: String
  , cipherKeyExchangeAlgorithm :: KeyExchangeAlgorithm
  , cipherIdentifier           :: (Word8, Word8)
  , cipherType                 :: CipherType
  , cipherIVLength             :: Word8
  , cipherEncryptionKeyLength  :: Int64
  , cipherHashAlgorithm        :: HashAlgorithm
  , cipherSignatureAlgorithm   :: SignatureAlgorithm
  , cipherEncryptor            :: ByteString -> ByteString ->
                                  ByteString -> ByteString ->
                                  ByteString -> ByteString ->
                                  Encryptor
  }

instance Show CipherSuite where
  show = cipherName

instance Eq CipherSuite where
  cs1 == cs2 = cipherName cs1 == cipherName cs2

data CipherType = StreamCipher | BlockCipher | AEADCipher

-- ----------------------------------------------------------------------------

cipherRequiresServerCert :: CipherSuite -> Bool
cipherRequiresServerCert cs = cipherKeyExchangeAlgorithm cs /= ExchDH_anon

cipherVerifyDataLength :: CipherSuite -> Int64
cipherVerifyDataLength _ = 12

cipherMACKeyLength :: CipherSuite -> Int64
cipherMACKeyLength = hashAlgorithmLength . cipherHashAlgorithm

-- ----------------------------------------------------------------------------

putCipherSuite :: CipherSuite -> Put
putCipherSuite CipherSuite{ cipherIdentifier = (a,b) } =
  do putWord8 a
     putWord8 b

getCipherSuite :: [CipherSuite] -> Get CipherSuite
getCipherSuite suites =
  do a <- getWord8
     b <- getWord8
     case find (\ x -> (a,b) == cipherIdentifier x) suites of
       Nothing -> return CipherSuite {
                    cipherName = "TLS_UNKNOWN_" ++ showHex a "" ++ "_" ++
                                 showHex b ""
                  , cipherKeyExchangeAlgorithm = ExchNull
                  , cipherIdentifier           = (a, b)
                  , cipherType                 = error "unknown cipher type"
                  , cipherIVLength             = error "unknown IV len"
                  , cipherEncryptionKeyLength  = error "unknown key len"
                  , cipherHashAlgorithm        = error "unknown hash alg"
                  , cipherSignatureAlgorithm   = error "unknown sig alg"
                  , cipherEncryptor            = error "unknown encryptor"
                  }
       Just cs -> return cs

-- ----------------------------------------------------------------------------

suiteTLS_NULL_WITH_NULL_NULL :: CipherSuite
suiteTLS_NULL_WITH_NULL_NULL = CipherSuite {
    cipherName                 = "TLS_NULL_WITH_NULL_NULL"
  , cipherKeyExchangeAlgorithm = ExchNull
  , cipherIdentifier           = (0x00, 0x00)
  , cipherType                 = StreamCipher
  , cipherIVLength             = 0
  , cipherEncryptionKeyLength  = 0
  , cipherHashAlgorithm        = HashNone
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildStreamEncryptor nullHash (undefined :: NullKey)
  }

suiteTLS_RSA_WITH_NULL_MD5 :: CipherSuite
suiteTLS_RSA_WITH_NULL_MD5 = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_NULL_MD5"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x01)
  , cipherType                 = StreamCipher
  , cipherIVLength             = 0
  , cipherEncryptionKeyLength  = 0
  , cipherHashAlgorithm        = HashMD5
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildStreamEncryptor md5' (undefined :: NullKey)
  }

suiteTLS_RSA_WITH_NULL_SHA :: CipherSuite
suiteTLS_RSA_WITH_NULL_SHA = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_NULL_SHA"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x02)
  , cipherType                 = StreamCipher
  , cipherIVLength             = 0
  , cipherEncryptionKeyLength  = 0
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildStreamEncryptor sha1' (undefined :: NullKey)
  }

suiteTLS_RSA_WITH_NULL_SHA256 :: CipherSuite
suiteTLS_RSA_WITH_NULL_SHA256 = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_NULL_SHA256"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x3B)
  , cipherType                 = StreamCipher
  , cipherIVLength             = 0
  , cipherEncryptionKeyLength  = 0
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildStreamEncryptor sha256' (undefined :: NullKey)
  }

suiteTLS_RSA_WITH_RC4_128_MD5 :: CipherSuite
suiteTLS_RSA_WITH_RC4_128_MD5 = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_RC4_128_MD5"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x04)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashMD5
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildStreamEncryptor md5' (undefined :: RC4Key)
  }

suiteTLS_RSA_WITH_RC4_128_SHA :: CipherSuite
suiteTLS_RSA_WITH_RC4_128_SHA = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_RC4_128_SHA"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x05)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildStreamEncryptor sha1' (undefined :: RC4Key)
  }

suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA :: CipherSuite
suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x0A)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 8
  , cipherEncryptionKeyLength  = 168 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: TDESKey)
  }

suiteTLS_RSA_WITH_AES_128_CBC_SHA :: CipherSuite
suiteTLS_RSA_WITH_AES_128_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_AES_128_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x2F)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey128)
  }

suiteTLS_RSA_WITH_AES_256_CBC_SHA :: CipherSuite
suiteTLS_RSA_WITH_AES_256_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_AES_256_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x35)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey256)
  }

suiteTLS_RSA_WITH_AES_128_CBC_SHA256 :: CipherSuite
suiteTLS_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_AES_128_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x3C)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey128)
  }

suiteTLS_RSA_WITH_AES_256_CBC_SHA256 :: CipherSuite
suiteTLS_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_RSA_WITH_AES_256_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchRSA
  , cipherIdentifier           = (0x00, 0x3D)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey256)
  }

suiteTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA :: CipherSuite
suiteTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_DSS
  , cipherIdentifier           = (0x00, 0x0D)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 8
  , cipherEncryptionKeyLength  = 168 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: TDESKey)
  }

suiteTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA :: CipherSuite
suiteTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_RSA
  , cipherIdentifier           = (0x00, 0x10)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 8
  , cipherEncryptionKeyLength  = 168 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: TDESKey)
  }

suiteTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA :: CipherSuite
suiteTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDHE_DSS
  , cipherIdentifier           = (0x00, 0x13)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 8
  , cipherEncryptionKeyLength  = 168 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: TDESKey)
  }

suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA :: CipherSuite
suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDHE_RSA
  , cipherIdentifier           = (0x00, 0x16)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 8
  , cipherEncryptionKeyLength  = 168 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: TDESKey)
  }

suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA :: CipherSuite
suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_DSS
  , cipherIdentifier           = (0x00, 0x30)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey128)
  }

suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA :: CipherSuite
suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_RSA
  , cipherIdentifier           = (0x00, 0x31)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey128)
  }

suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA :: CipherSuite
suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDHE_DSS
  , cipherIdentifier           = (0x00, 0x32)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey128)
  }

suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA :: CipherSuite
suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDHE_RSA
  , cipherIdentifier           = (0x00, 0x33)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey128)
  }

suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA :: CipherSuite
suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_DSS
  , cipherIdentifier           = (0x00, 0x36)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey256)
  }

suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA :: CipherSuite
suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_RSA
  , cipherIdentifier           = (0x00, 0x37)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey256)
  }

suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA :: CipherSuite
suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDHE_DSS
  , cipherIdentifier           = (0x00, 0x38)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey256)
  }

suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA :: CipherSuite
suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDHE_RSA
  , cipherIdentifier           = (0x00, 0x39)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey256)
  }

suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA256 :: CipherSuite
suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDH_DSS
  , cipherIdentifier           = (0x00, 0x3E)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey128)
  }

suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA256 :: CipherSuite
suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDH_RSA
  , cipherIdentifier           = (0x00, 0x3F)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey128)
  }

suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA256 :: CipherSuite
suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDHE_DSS
  , cipherIdentifier           = (0x00, 0x40)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey128)
  }

suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :: CipherSuite
suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDHE_RSA
  , cipherIdentifier           = (0x00, 0x67)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey128)
  }

suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA256 :: CipherSuite
suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDH_DSS
  , cipherIdentifier           = (0x00, 0x68)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey256)
  }

suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA256 :: CipherSuite
suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDH_RSA
  , cipherIdentifier           = (0x00, 0x69)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey256)
  }

suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA256 :: CipherSuite
suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDHE_DSS
  , cipherIdentifier           = (0x00, 0x6A)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigDSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey256)
  }

suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :: CipherSuite
suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDHE_RSA
  , cipherIdentifier           = (0x00, 0x6B)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigRSA
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey256)
  }

suiteTLS_DH_anon_WITH_RC4_128_MD5 :: CipherSuite
suiteTLS_DH_anon_WITH_RC4_128_MD5 = CipherSuite {
    cipherName                 = "TLS_DH_anon_WITH_RC4_128_MD5"
  , cipherKeyExchangeAlgorithm = ExchDH_anon
  , cipherIdentifier           = (0x00, 0x18)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashMD5
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildStreamEncryptor md5' (undefined :: RC4Key)
  }

suiteTLS_DH_anon_WITH_3DES_EDE_CBC_SHA :: CipherSuite
suiteTLS_DH_anon_WITH_3DES_EDE_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_anon
  , cipherIdentifier           = (0x00, 0x1B)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 8
  , cipherEncryptionKeyLength  = 168 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: TDESKey)
  }

suiteTLS_DH_anon_WITH_AES_128_CBC_SHA :: CipherSuite
suiteTLS_DH_anon_WITH_AES_128_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_anon
  , cipherIdentifier           = (0x00, 0x34)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey128)
  }

suiteTLS_DH_anon_WITH_AES_256_CBC_SHA :: CipherSuite
suiteTLS_DH_anon_WITH_AES_256_CBC_SHA = CipherSuite {
    cipherName                 = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
  , cipherKeyExchangeAlgorithm = ExchDH_anon
  , cipherIdentifier           = (0x00, 0x3A)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA1
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildBlockEncryptor sha1' (undefined :: AESKey256)
  }

suiteTLS_DH_anon_WITH_AES_128_CBC_SHA256 :: CipherSuite
suiteTLS_DH_anon_WITH_AES_128_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDH_anon
  , cipherIdentifier           = (0x00, 0x6C)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 16
  , cipherEncryptionKeyLength  = 128 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey128)
  }

suiteTLS_DH_anon_WITH_AES_256_CBC_SHA256 :: CipherSuite
suiteTLS_DH_anon_WITH_AES_256_CBC_SHA256 = CipherSuite {
    cipherName                 = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
  , cipherKeyExchangeAlgorithm = ExchDH_anon
  , cipherIdentifier           = (0x00, 0x6D)
  , cipherType                 = BlockCipher
  , cipherIVLength             = 32
  , cipherEncryptionKeyLength  = 256 `div` 8
  , cipherHashAlgorithm        = HashSHA256
  , cipherSignatureAlgorithm   = SigAnonymous
  , cipherEncryptor            = buildBlockEncryptor sha256' (undefined :: AESKey256)
  }

rfc5246CipherSuites :: [CipherSuite]
rfc5246CipherSuites = [
    suiteTLS_NULL_WITH_NULL_NULL
  , suiteTLS_RSA_WITH_NULL_MD5
  , suiteTLS_RSA_WITH_NULL_SHA
  , suiteTLS_RSA_WITH_NULL_SHA256
  , suiteTLS_RSA_WITH_RC4_128_MD5
  , suiteTLS_RSA_WITH_RC4_128_SHA
  , suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_RSA_WITH_AES_128_CBC_SHA256
  , suiteTLS_RSA_WITH_AES_256_CBC_SHA256
  , suiteTLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA
  , suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA
  , suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA
  , suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA
  , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_DH_DSS_WITH_AES_128_CBC_SHA256
  , suiteTLS_DH_RSA_WITH_AES_128_CBC_SHA256
  , suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA256
  , suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA256
  , suiteTLS_DH_DSS_WITH_AES_256_CBC_SHA256
  , suiteTLS_DH_RSA_WITH_AES_256_CBC_SHA256
  , suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA256
  , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  , suiteTLS_DH_anon_WITH_RC4_128_MD5
  , suiteTLS_DH_anon_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_DH_anon_WITH_AES_128_CBC_SHA
  , suiteTLS_DH_anon_WITH_AES_256_CBC_SHA
  , suiteTLS_DH_anon_WITH_AES_128_CBC_SHA256
  , suiteTLS_DH_anon_WITH_AES_256_CBC_SHA256
  ]

-- ----------------------------------------------------------------------------

sha1' :: ByteString -> ByteString
sha1' = bytestringDigest . sha1

sha256' :: ByteString -> ByteString
sha256' = bytestringDigest . sha256

md5' :: ByteString -> ByteString
md5' = encodeLazy . md5


