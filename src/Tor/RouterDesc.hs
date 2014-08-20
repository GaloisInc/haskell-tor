module Tor.RouterDesc(
         RouterDesc(..)
       , ExitRule(..)
       , AddrSpec(..)
       , PortSpec(..)
       )
 where

import Codec.Crypto.RSA
import Data.ByteString.Lazy(ByteString)
import Data.Time
import Data.Word

data RouterDesc = RouterDesc {
       routerNickname                :: String
     , routerIPv4Address             :: String
     , routerORPort                  :: Word16
     , routerDirPort                 :: Maybe Word16
     , routerParseLog                :: [String]
     , routerAvgBandwidth            :: Int
     , routerBurstBandwidth          :: Int
     , routerObservedBandwidth       :: Int
     , routerPlatformName            :: String
     , routerEntryPublished          :: UTCTime
     , routerFingerprint             :: ByteString
     , routerHibernating             :: Bool
     , routerUptime                  :: Maybe Integer
     , routerOnionKey                :: PublicKey
     , routerNTorOnionKey            :: Maybe ByteString
     , routerSigningKey              :: PublicKey
     , routerExitRules               :: [ExitRule]
     , routerIPv6Policy              :: Either [PortSpec] [PortSpec]
     , routerSignature               :: ByteString
     , routerContact                 :: Maybe String
     , routerFamily                  :: [(Maybe ByteString, Maybe String)]
     , routerReadHistory             :: Maybe (UTCTime, Int, [Int])
     , routerWriteHistory            :: Maybe (UTCTime, Int, [Int])
     , routerCachesExtraInfo         :: Bool
     , routerExtraInfoDigest         :: Maybe ByteString
     , routerHiddenServiceDir        :: Maybe Int
     , routerLinkProtocolVersions    :: [Int]
     , routerCircuitProtocolVersions :: [Int]
     , routerAllowSingleHopExits     :: Bool
     , routerAlternateORAddresses    :: [(String, Word16)]
     }
 deriving (Show)

data ExitRule = ExitRuleAccept AddrSpec PortSpec
              | ExitRuleReject AddrSpec PortSpec
 deriving (Show)

data PortSpec = PortSpecAll
              | PortSpecRange  Word16 Word16
              | PortSpecSingle Word16
 deriving (Eq, Show)

data AddrSpec = AddrSpecAll
              | AddrSpecIP4     String
              | AddrSpecIP4Mask String String
              | AddrSpecIP4Bits String Int
              | AddrSpecIP6     String
              | AddrSpecIP6Bits String Int
 deriving (Eq, Show)


