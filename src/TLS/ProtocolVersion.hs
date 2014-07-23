module TLS.ProtocolVersion(
         ProtocolVersion(..)
       , putProtocolVersion
       , getProtocolVersion
       , versionTLS1_0
       , versionTLS1_1
       , versionTLS1_2
       )
 where

import Control.Applicative
import Data.Binary.Get
import Data.Binary.Put
import Data.Word

data ProtocolVersion = ProtocolVersion {
    pvMajor :: Word8
  , pvMinor :: Word8
  }
 deriving (Eq, Show)

instance Ord ProtocolVersion where
  compare a b = case compare (pvMajor a) (pvMajor b) of
                  EQ -> compare (pvMinor a) (pvMinor b)
                  x  -> x

putProtocolVersion :: ProtocolVersion -> Put
putProtocolVersion pv =
  do putWord8 (pvMajor pv)
     putWord8 (pvMinor pv)

getProtocolVersion :: Get ProtocolVersion
getProtocolVersion = ProtocolVersion <$> getWord8 <*> getWord8

-- ----------------------------------------------------------------------------

versionTLS1_0 :: ProtocolVersion
versionTLS1_0  = ProtocolVersion 3 1

versionTLS1_1 :: ProtocolVersion
versionTLS1_1  = ProtocolVersion 3 2

versionTLS1_2 :: ProtocolVersion
versionTLS1_2  = ProtocolVersion 3 3
