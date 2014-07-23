module Test.HMAC(hmacTests) where

import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.ByteString.Lazy.Char8(pack)
import Data.Char
import Data.List(isPrefixOf)
import Data.Word
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)
import TLS.CipherSuite.HMAC

hmacTest :: String -> (ByteString -> ByteString -> ByteString) ->
            ByteString -> ByteString -> ByteString ->
            Test
hmacTest name hmacf keyv val result =
  testCase name (assertEqual "" (hmacf keyv val) result)

hmacTests :: Test
hmacTests =
  testGroup "HMAC Tests" [
      hmacTest "Wikipedia MD5 Example #1" hmac_md5 BS.empty BS.empty
        (dehex "0x74e6f7298a9c2d168935f58c001bad88")
    , hmacTest "Wikipedia SHA1 Example #1" hmac_sha1 BS.empty BS.empty
        (dehex "0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
    , hmacTest "Wikipedia SHA256 Example #1" hmac_sha256 BS.empty BS.empty
        (dehex "0xb613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
    , hmacTest "Wikipedia MD5 Example #2" hmac_md5 key quickBrown
        (dehex "0x80070713463e7749b90c2dc24911e275")
    , hmacTest "Wikipedia SHA1 Example #2" hmac_sha1 key quickBrown
        (dehex "0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
    , hmacTest "Wikipedia SHA256 Example #2" hmac_sha256 key quickBrown
        (dehex "0xf7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    , hmacTest "RFC2104 Test #1" hmac_md5 (BS.replicate 16 0xb) (pack "Hi There")
        (dehex "0x9294727a3638bb1c13f48ef8158bfc9d")
    , hmacTest "RFC2104 Test #2" hmac_md5 (pack "Jefe") (pack "what do ya want for nothing?")
        (dehex "0x750c783e6ab0b503eaa86e310a5db738")
    , hmacTest "RFC2104 Test #3" hmac_md5 (BS.replicate 16 0xAA) (BS.replicate 50 0xDD)
        (dehex "0x56be34521d144c88dbb8c733f0e8b3f6")
    -- FIXME: More test vectors: RFC 4231 and others?
  ]

key :: ByteString
key = pack "key"

quickBrown :: ByteString
quickBrown = pack "The quick brown fox jumps over the lazy dog"

dehex :: String -> ByteString
dehex str =
  let base | "0x" `isPrefixOf` str = drop 2 str
           | otherwise             = str
      rbase = reverse base
      bytes = pullBytes rbase
  in BS.pack (reverse bytes)
 where
  pullBytes :: [Char] -> [Word8]
  pullBytes []              = []
  pullBytes [x]             = [digitToInt' x]
  pullBytes (low:high:rest) =
    ((digitToInt' high * 16) + digitToInt' low) : pullBytes rest
  --
  digitToInt' = fromIntegral . digitToInt
