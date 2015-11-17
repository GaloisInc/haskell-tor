-- |Handy shorthands for dealing with cryptographic hashes.
module Crypto.Hash.Easy(sha1, sha256,
                        sha1lazy, sha256lazy,
                        noHash)
 where

import Crypto.Hash
import Data.ByteArray
import Data.ByteString(ByteString)
import qualified Data.ByteString.Lazy as L

type HashLazy a = L.ByteString -> Digest a

-- |Generate a SHA1 hash of a bytestring.
sha1 :: ByteString -> ByteString
sha1 = convert . hashWith SHA1

-- |Generate a SHA256 hash of a bytestring.
sha256 :: ByteString -> ByteString
sha256 = convert . hashWith SHA256

-- |Generate a SHA1 hash of a lazy bytestring.
sha1lazy :: L.ByteString -> L.ByteString
sha1lazy = L.fromStrict . convert . (hashlazy :: HashLazy SHA1)

-- |Generate a SHA256 hash of a lazy bytestring.
sha256lazy :: L.ByteString -> L.ByteString
sha256lazy = L.fromStrict . convert . (hashlazy :: HashLazy SHA256)

-- |When generating a signautre, don't include any information about the
-- underlying hash function.
noHash :: Maybe SHA256
noHash = Nothing
