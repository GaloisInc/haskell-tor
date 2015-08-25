module Crypto.Hash.Easy(sha1, sha256,
                        sha1lazy, sha256lazy,
                        noHash)
 where

import Crypto.Hash
import Data.ByteArray
import Data.ByteString(ByteString)
import qualified Data.ByteString.Lazy as L

type HashLazy a = L.ByteString -> Digest a

sha1 :: ByteString -> ByteString
sha1 = convert . hashWith SHA1

sha256 :: ByteString -> ByteString
sha256 = convert . hashWith SHA256

sha1lazy :: L.ByteString -> L.ByteString
sha1lazy = L.fromStrict . convert . (hashlazy :: HashLazy SHA1)

sha256lazy :: L.ByteString -> L.ByteString
sha256lazy = L.fromStrict . convert . (hashlazy :: HashLazy SHA256)

noHash :: Maybe SHA256
noHash = Nothing
