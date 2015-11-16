module Tor.RouterDesc(
         RouterDesc(..)
       , blankRouterDesc
       , NodeFamily(..)
       , ExitRule(..)
       , AddrSpec(..)
       , PortSpec(..)
       )
 where

import Crypto.PubKey.Curve25519 as Curve
import Crypto.PubKey.RSA as RSA
import Data.ByteString(ByteString, empty)
import Data.Hourglass
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
     , routerEntryPublished          :: DateTime
     , routerFingerprint             :: ByteString
     , routerHibernating             :: Bool
     , routerUptime                  :: Maybe Integer
     , routerOnionKey                :: RSA.PublicKey
     , routerNTorOnionKey            :: Maybe Curve.PublicKey
     , routerSigningKey              :: RSA.PublicKey
     , routerExitRules               :: [ExitRule]
     , routerIPv6Policy              :: Either [PortSpec] [PortSpec]
     , routerSignature               :: ByteString
     , routerContact                 :: Maybe String
     , routerFamily                  :: [NodeFamily]
     , routerReadHistory             :: Maybe (DateTime, Int, [Int])
     , routerWriteHistory            :: Maybe (DateTime, Int, [Int])
     , routerCachesExtraInfo         :: Bool
     , routerExtraInfoDigest         :: Maybe ByteString
     , routerHiddenServiceDir        :: Maybe Int
     , routerLinkProtocolVersions    :: [Int]
     , routerCircuitProtocolVersions :: [Int]
     , routerAllowSingleHopExits     :: Bool
     , routerAlternateORAddresses    :: [(String, Word16)]
     , routerStatus                  :: [String]
     }
 deriving (Show)

instance Eq RouterDesc where
  a == b = routerSigningKey a == routerSigningKey b

blankRouterDesc :: RouterDesc
blankRouterDesc =
  RouterDesc {
    routerNickname                = ""
  , routerIPv4Address             = "0.0.0.0"
  , routerORPort                  = 0
  , routerDirPort                 = Nothing
  , routerParseLog                = []
  , routerAvgBandwidth            = 0
  , routerBurstBandwidth          = 0
  , routerObservedBandwidth       = 0
  , routerPlatformName            = "Haskell"
  , routerEntryPublished          = timeFromElapsed (Elapsed (Seconds 0))
  , routerFingerprint             = empty
  , routerHibernating             = False
  , routerUptime                  = Nothing
  , routerOnionKey                = error "No public onion key"
  , routerNTorOnionKey            = Nothing
  , routerSigningKey              = error "No signing key"
  , routerExitRules               = []
  , routerIPv6Policy              = Left []
  , routerSignature               = empty
  , routerContact                 = Nothing
  , routerFamily                  = []
  , routerReadHistory             = Nothing
  , routerWriteHistory            = Nothing
  , routerCachesExtraInfo         = False
  , routerExtraInfoDigest         = Nothing
  , routerHiddenServiceDir        = Nothing
  , routerLinkProtocolVersions    = []
  , routerCircuitProtocolVersions = []
  , routerAllowSingleHopExits     = False
  , routerAlternateORAddresses    = []
  , routerStatus                  = []
  }

data NodeFamily = NodeFamilyNickname String
                | NodeFamilyDigest ByteString
                | NodeFamilyBoth String ByteString
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


