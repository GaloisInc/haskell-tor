module TLS.CipherSuite.PRF(prf) where

import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.ByteString.Lazy.Char8(pack)
import Data.Digest.Pure.SHA.HMAC

prf :: ByteString -> String -> ByteString -> ByteString
prf secret label seed = p_hash hmacSha256 secret (label' `BS.append` seed)
 where label' = pack label

p_hash :: (ByteString -> ByteString -> ByteString) ->
          ByteString -> ByteString ->
          ByteString
p_hash hashHMAC secret seed =
  BS.concat $ map (\ a_n -> hashHMAC secret (a_n `BS.append` seed))
                  (tail (infinite_a hashHMAC secret seed))

infinite_a :: (ByteString -> ByteString -> ByteString) ->
              ByteString -> ByteString ->
              [ByteString]
infinite_a hashHMAC secret seed = iterate a seed
 where
  a prev = hashHMAC secret prev

