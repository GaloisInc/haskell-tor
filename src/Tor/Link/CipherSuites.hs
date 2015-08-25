module Tor.Link.CipherSuites(
         suiteTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
       , suiteTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA
       , suiteTLS_ECDH_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
       , suiteTLS_RSA_WITH_AES_256_CBC_SHA
       , suiteTLS_ECDHE_ECDSA_WITH_RC4_128_SHA
       , suiteTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
       , suiteTLS_ECDHE_RSA_WITH_RC4_128_SHA
       , suiteTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA
       , suiteTLS_ECDH_RSA_WITH_RC4_128_SHA
       , suiteTLS_ECDH_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_ECDH_ECDSA_WITH_RC4_128_SHA
       , suiteTLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
       , suiteTLS_RSA_WITH_RC4_128_MD5
       , suiteTLS_RSA_WITH_RC4_128_SHA
       , suiteTLS_RSA_WITH_AES_128_CBC_SHA
       , suiteTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteSSL3_EDH_RSA_DES_192_CBC3_SHA
       , suiteSSL3_EDH_DSS_DES_192_CBC3_SHA
       , suiteTLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
       , suiteSSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
       , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256
       )
 where

import Data.ByteArray
import Data.ByteString(ByteString)
import qualified Data.ByteString as B
import Network.TLS
import Crypto.Cipher.AES
import Crypto.Cipher.TripleDES
import Crypto.Cipher.RC4
import Crypto.Cipher.Types hiding(Cipher, cipherName)
import qualified Crypto.Cipher.Types as C
import Crypto.Error

-- -----------------------------------------------------------------------------

prep :: (C.Cipher c, BlockCipher c, ByteArray key) =>
        key -> (c -> IV c -> ByteString -> ByteString) -> c ->
        BulkBlock
prep key f _ iv input =
  let output = f ctx (makeIV_ iv) input
  in (output, takeLast 16 output)
 where
  ctx          = noFail (cipherInit key)
  makeIV_      = maybe (error "makeIV_") id . makeIV
  takeLast i b = B.drop (B.length b - i) b

noFail :: CryptoFailable a -> a
noFail = throwCryptoError

bulkAES128 :: Bulk
bulkAES128 =
  Bulk {
    bulkName      = "AES128"
  , bulkKeySize   = 16
  , bulkIVSize    = 16
  , bulkBlockSize = 16
  , bulkF         = BulkBlockF aes128cbc
  }
 where
  aes128cbc BulkEncrypt key = prep key cbcEncrypt (undefined :: AES128)
  aes128cbc BulkDecrypt key = prep key cbcDecrypt (undefined :: AES128)

bulkAES256 :: Bulk
bulkAES256 =
  Bulk {
    bulkName      = "AES256"
  , bulkKeySize   = 32
  , bulkIVSize    = 16
  , bulkBlockSize = 16
  , bulkF         = BulkBlockF aes256cbc
  }
 where
  aes256cbc BulkEncrypt key = prep key cbcEncrypt (undefined :: AES256)
  aes256cbc BulkDecrypt key = prep key cbcDecrypt (undefined :: AES256)

bulk3DES :: Bulk
bulk3DES =
  Bulk {
    bulkName      = "3DES-EDE-CBC"
  , bulkKeySize   = 24
  , bulkIVSize    = 8
  , bulkBlockSize = 8
  , bulkF         = BulkBlockF tripledes
  }
 where
  tripledes BulkEncrypt key = prep key cbcEncrypt (undefined :: DES_EDE3)
  tripledes BulkDecrypt key = prep key cbcDecrypt (undefined :: DES_EDE3)

bulkRC4 :: Bulk
bulkRC4 =
  Bulk {
    bulkName      = "RC4-128"
  , bulkKeySize   = 16
  , bulkIVSize    = 0
  , bulkBlockSize = 0
  , bulkF         = BulkStreamF rc4
  }
 where
  rc4 _ bulkKey = BulkStream (combineRC4 (initialize bulkKey))
  combineRC4 ctx input =
    let (ctx', output) = combine ctx input
    in (output, BulkStream (combineRC4 ctx'))

-- -----------------------------------------------------------------------------

suiteTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0xc009
  , cipherName        = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0xc014
  , cipherName        = "TLS_ECDHE_RSA_WIT_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0x0039
  , cipherName        = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_DHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0x0038
  , cipherName        = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_DHE_DSS
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_RSA_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_ECDH_RSA_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0xc00f
  , cipherName        = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0xc005
  , cipherName        = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_RSA_WITH_AES_256_CBC_SHA :: Cipher
suiteTLS_RSA_WITH_AES_256_CBC_SHA =
  Cipher {
    cipherID          = 0x0035
  , cipherName        = "TLS_RSA_WITH_AES_256_CBC_SHA"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_ECDSA_WITH_RC4_128_SHA :: Cipher
suiteTLS_ECDHE_ECDSA_WITH_RC4_128_SHA =
  Cipher {
    cipherID          = 0xc007
  , cipherName        = "TLS_ECDHE_ECDSA_WITH_RC4"
  , cipherBulk        = bulkRC4
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0xc009
  , cipherName        = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_RSA_WITH_RC4_128_SHA :: Cipher
suiteTLS_ECDHE_RSA_WITH_RC4_128_SHA =
  Cipher {
    cipherID          = 0xc011
  , cipherName        = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
  , cipherBulk        = bulkRC4
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0xc013
  , cipherName        = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0x0033
  , cipherName        = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_DHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0x0032
  , cipherName        = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_DHE_DSS
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_RSA_WITH_RC4_128_SHA :: Cipher
suiteTLS_ECDH_RSA_WITH_RC4_128_SHA =
  Cipher {
    cipherID          = 0xc00c
  , cipherName        = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
  , cipherBulk        = bulkRC4
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_RSA_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_ECDH_RSA_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0xc00e
  , cipherName        = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_ECDSA_WITH_RC4_128_SHA :: Cipher
suiteTLS_ECDH_ECDSA_WITH_RC4_128_SHA =
  Cipher {
    cipherID          = 0xc002
  , cipherName        = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
  , cipherBulk        = bulkRC4
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0xc004
  , cipherName        = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_RSA_WITH_RC4_128_MD5 :: Cipher
suiteTLS_RSA_WITH_RC4_128_MD5 =
  Cipher {
    cipherID          = 0x0004
  , cipherName        = "TLS_RSA_WITH_RC4_128_MD5"
  , cipherBulk        = bulkRC4
  , cipherHash        = MD5
  , cipherKeyExchange = CipherKeyExchange_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_RSA_WITH_RC4_128_SHA :: Cipher
suiteTLS_RSA_WITH_RC4_128_SHA =
  Cipher {
    cipherID          = 0x0005
  , cipherName        = "TLS_RSA_WITH_RC4_128_SHA"
  , cipherBulk        = bulkRC4
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_RSA_WITH_AES_128_CBC_SHA :: Cipher
suiteTLS_RSA_WITH_AES_128_CBC_SHA =
  Cipher {
    cipherID          = 0x002f
  , cipherName        = "TLS_RSA_WITH_AES_128_CBC_SHA"
  , cipherBulk        = bulkAES128
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0xc008
  , cipherName        = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0xc012
  , cipherName        = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteTLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0xc00d
  , cipherName        = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteTLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0xc003
  , cipherName        = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_ECDSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0x000a
  , cipherName        = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_RSA
  , cipherMinVer      = Just TLS12
  }

suiteSSL3_EDH_RSA_DES_192_CBC3_SHA :: Cipher
suiteSSL3_EDH_RSA_DES_192_CBC3_SHA =
  Cipher {
    cipherID          = 0x0016
  , cipherName        = "SSL3_EDH_RSA_DES_192_CBC3_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_ECDH_RSA
  , cipherMinVer      = Just SSL3
  }

suiteSSL3_EDH_DSS_DES_192_CBC3_SHA :: Cipher
suiteSSL3_EDH_DSS_DES_192_CBC3_SHA =
  Cipher {
    cipherID          = 0x0013
  , cipherName        = "SSL3_EDH_DSS_DES_192_CBC3_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_DH_DSS -- FIXME: THIS IS WRONG
  , cipherMinVer      = Just SSL3
  }

suiteSSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteSSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0xFEFF
  , cipherName        = "SSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_RSA
  , cipherMinVer      = Just SSL3
  }

suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA :: Cipher
suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA =
  Cipher {
    cipherID          = 0x0016
  , cipherName        = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
  , cipherBulk        = bulk3DES
  , cipherHash        = SHA1
  , cipherKeyExchange = CipherKeyExchange_DHE_RSA
  , cipherMinVer      = Just TLS12
  }

suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :: Cipher
suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256 =
  Cipher {
    cipherID          = 0x006B
  , cipherName        = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
  , cipherBulk        = bulkAES256
  , cipherHash        = SHA256
  , cipherKeyExchange = CipherKeyExchange_DHE_RSA
  , cipherMinVer      = Just TLS12
  }


