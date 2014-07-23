{-# LANGUAGE RecordWildCards #-}
-- |Functions and curves for performing Diffie-Hellman key agreement across two
-- systems. For a very nice, high-level description of how Diffie-Hellman works,
-- I recommend the Wikipedia article:
--    <http://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange>
module TLS.DiffieHellman(
         -- * TLS Diffie-Hellman-based structures
         PublicValueEncoding(..)
       , ServerDHParams(..), putServerDHParams, getServerDHParams
       , ClientDiffieHellmanPublic(..), getClientDH, putClientDH
         -- * Conversion from TLS structures to standard Diffie-Hellman
         -- interpretations
       , DiffieHellmanGroup(..)
       , serverDHParamsToGroup, groupToServerDHParams
       , clientPublicToInteger, integerToClientPublic
         -- * Diffie-Hellman computations of note.
       , generateLocal, computePublicValue, computeSharedSecret
         -- * Standard Diffie-Hellman curves
       , oakley1, oakley2
       , modp1536, modp2048, modp3072, modp4096, modp6144, modp8192
       )
 where

import Codec.Crypto.RSA.Pure
import qualified Codec.Crypto.RSA.Exceptions as E
import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString      as BSS

-- |The TLS 1.2 structure for communicating the public, server-side
-- Diffie-Hellman values.
data ServerDHParams = ServerDHParams {
       dhP  :: ByteString
     , dhG  :: ByteString
     , dhYs :: ByteString
     }
 deriving (Eq, Show)

-- |Parse into a TLS 1.2 ServerDHParams. Will 'fail' upon various violations
-- of ServerDHParams assumptions, such as the length of the numbers being
-- between 1 and 65535.
getServerDHParams :: Get ServerDHParams
getServerDHParams =
  do l1   <- getWord16be
     unless (l1 >= 1) $
       fail "dhP value too short in read DHParams."
     unless (l1 <= 65535) $
       fail "dhP value too long in read DHParams."
     dhP  <- getLazyByteString (fromIntegral l1)
     l2   <- getWord16be
     unless (l2 >= 1) $
       fail "dhG value too short in read DHParams."
     unless (l2 <= 65535) $
       fail "dhG value too long in read DHParams."
     dhG  <- getLazyByteString (fromIntegral l2)
     l3   <- getWord16be
     unless (l3 >= 1) $
       fail "dhYs value too short in read DHParams."
     unless (l3 <= 65535) $
       fail "dhYs value too long in read DHParams."
     dhYs <- getLazyByteString (fromIntegral l3)
     return ServerDHParams{ .. }

-- |Synthesize a ServerDHParams structure. Will 'fail' upon various violations
-- of ServerDHParams assumptions, such as the length of the numbers being
-- between 1 and 65535.
putServerDHParams :: ServerDHParams -> Put
putServerDHParams sp =
  do unless (BS.length (dhP sp) >= 1) $
       fail "dhP value is too short."
     unless (BS.length (dhP sp) <= 65535) $
       fail "dhP value is too long."
     unless (BS.length (dhG sp) >= 1) $
       fail "dhG value is too short."
     unless (BS.length (dhG sp) <= 65535) $
       fail "dhG value is too long."
     unless (BS.length (dhYs sp) >= 1) $
       fail "dhYs value is too short."
     unless (BS.length (dhYs sp) <= 65535) $
       fail "dhYs value is too long."
     putWord16be (fromIntegral (BS.length (dhP sp)))
     putLazyByteString (dhP sp)
     putWord16be (fromIntegral (BS.length (dhG sp)))
     putLazyByteString (dhG sp)
     putWord16be (fromIntegral (BS.length (dhYs sp)))
     putLazyByteString (dhYs sp)

-- ----------------------------------------------------------------------------

-- |Whether the DiffieHellman information for a connection is part of the
-- certificates (implicit) or explicitly negotiated (explicit).
data PublicValueEncoding = Implicit | Explicit

-- |The TLS 1.2 format for client Diffie-Hellman information.
data ClientDiffieHellmanPublic = ClientDHImplicit
                               | ClientDHExplicit { dhYc :: ByteString }
 deriving (Eq, Show)

getClientDH :: PublicValueEncoding -> Get ClientDiffieHellmanPublic
getClientDH Implicit = return ClientDHImplicit
getClientDH Explicit =
  do len <- getWord16be
     unless (len > 0) $
       fail "dhYc is too short reading ClientDiffieHellmanPublic."
     dhYc <- getLazyByteString (fromIntegral len)
     return ClientDHExplicit{..}

putClientDH :: ClientDiffieHellmanPublic -> Put
putClientDH ClientDHImplicit = return ()
putClientDH x@ClientDHExplicit{} =
  do unless (BS.length (dhYc x) >= 1) $
       fail "dhYc is too short writing ClientDiffieHellmanPublic."
     unless (BS.length (dhYc x) <= 65535) $
       fail "dhYc is too long writing ClientDiffieHellmanPublic."
     putWord16be (fromIntegral (BS.length (dhYc x)))
     putLazyByteString (dhYc x)

-- ----------------------------------------------------------------------------

-- |Convert the TLS 1.2 ServerDHParams structure into something a little more
-- handy for doing Diffie-Hellman computations: the group and the server-side
-- public value (Ys if you are reading RFCs, or capital A if you are reading
-- Wikipedia.)
serverDHParamsToGroup :: ServerDHParams -> (DiffieHellmanGroup, Integer)
serverDHParamsToGroup dhp = (group, ys)
 where
  ys    = os2ip (dhYs dhp)
  group = DiffieHellmanGroup {
    dhgP    = os2ip (dhP dhp)
  , dhgG    = os2ip (dhG dhp)
  , dhgSize = fromIntegral (BS.length (dhP dhp) * 8)
  }

-- |Convert a Diffie-Hellman Group and the server-side public value (Ys if you
-- are reading RFCs, or capital A if you are reading Wikipedia) into the TLS
-- structure ServerDHParams.
groupToServerDHParams :: DiffieHellmanGroup -> Integer -> ServerDHParams
groupToServerDHParams dhg ys = ServerDHParams {
    dhP  = BS.dropWhile (== 0) (E.i2osp (dhgP dhg) (dhgSize dhg))
  , dhG  = BS.dropWhile (== 0) (E.i2osp (dhgG dhg) (dhgSize dhg))
  , dhYs = BS.dropWhile (== 0) (E.i2osp ys         (dhgSize dhg))
  }

clientPublicToInteger :: ClientDiffieHellmanPublic -> Integer
clientPublicToInteger ClientDHImplicit =
  error "Cannot manufacture integer from implicit client DH."
clientPublicToInteger (ClientDHExplicit x) = os2ip x

integerToClientPublic :: DiffieHellmanGroup -> Integer ->
                         ClientDiffieHellmanPublic
integerToClientPublic dhg x = ClientDHExplicit (E.i2osp x (dhgSize dhg))

-- ----------------------------------------------------------------------------

-- |Given a Diffie-Hellman group and a random number generator, generate a
-- private value suitable for use in a Diffie-Hellman exchange. (If you are
-- reading Wikipedia, this is lowercase a or lowercase b.)
generateLocal :: CryptoRandomGen g =>
                 DiffieHellmanGroup -> g ->
                 Either GenError (Integer, g)
generateLocal dhg g =
  case genBytes (dhgSize dhg `div` 8) g of
    Left err                -> Left err
    Right (bstr, g')
      | BSS.all (== 0) bstr -> generateLocal dhg g'
      | otherwise           -> Right (os2ip (BS.fromStrict bstr), g')

-- |Given a Diffie-Hellman group and one of the private keys, generate the
-- public value associated with that key.
computePublicValue :: DiffieHellmanGroup -> Integer -> Integer
computePublicValue dhg a = modular_exponentiation (dhgG dhg) a (dhgP dhg)

-- |Given a Diffie-Hellman group, the other side's public value (capital A or B
-- from the Wikipedia article), and our private value (lowercase a or b from the
-- Wikipedia article), compute the shared key.
computeSharedSecret :: DiffieHellmanGroup -> Integer -> Integer -> ByteString
computeSharedSecret dhg pub priv = unpadded
 where
  base     = modular_exponentiation pub priv (dhgP dhg)
  padded   = E.i2osp base (dhgSize dhg)
  unpadded = BS.dropWhile (== 0) padded

-- ----------------------------------------------------------------------------

data DiffieHellmanGroup = DiffieHellmanGroup {
       dhgP    :: Integer -- ^The prime.
     , dhgG    :: Integer -- ^The generator.
     , dhgSize :: Int     -- ^Size in bits.
     }
 deriving (Eq, Show)

-- |Group 1 from RFC 2409
oakley1 :: DiffieHellmanGroup
oakley1 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 768
  }

-- |Group 2 from RFC 2409
oakley2 :: DiffieHellmanGroup
oakley2 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 1024
  }

-- |Group 5 from RFC 3526
modp1536 :: DiffieHellmanGroup
modp1536 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 1536
  }

-- |Group 14 from RFC 3526
modp2048 :: DiffieHellmanGroup
modp2048 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 2048
  }

-- |Group 15 from RFC 3526
modp3072 :: DiffieHellmanGroup
modp3072 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 3072
  }

-- |Group 16 from RFC 3526
modp4096 :: DiffieHellmanGroup
modp4096 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 4096
  }

-- |Group 17 from RFC 3526
modp6144 :: DiffieHellmanGroup
modp6144 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 6144
  }

-- |Group 18 from RFC 3526
modp8192 :: DiffieHellmanGroup
modp8192 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 8192
  }

