-- |Structures and rules for describing routers.
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

-- |The complete description of a router within the Tor network.
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

-- |A blank router description, with most of the options initialized with
-- standard "blank" values.
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

-- |A family descriptor for a node. Either a nickname, or a digest referencing
-- the family, or both.
data NodeFamily = NodeFamilyNickname String
                | NodeFamilyDigest ByteString
                | NodeFamilyBoth String ByteString
 deriving (Show)

-- |A rule for accepting or rejecting traffic, usually specified by exit nodes.
data ExitRule = ExitRuleAccept AddrSpec PortSpec -- ^Accept matching traffic.
              | ExitRuleReject AddrSpec PortSpec -- ^Reject matching traffic.
 deriving (Show)

-- |A port specifier
data PortSpec = PortSpecAll -- ^Accept any port
              | PortSpecRange  Word16 Word16 -- ^Accept ports between the two
                                             -- values, inclusive.
              | PortSpecSingle Word16 -- ^Accept only the given port.
 deriving (Eq, Show)

-- |An address or subnet specifier.
data AddrSpec = AddrSpecAll -- ^Accept any address
              | AddrSpecIP4     String -- ^Accept this specific address.
              | AddrSpecIP4Mask String String -- ^Accept this IP address and
                -- subnet mask (255.255.255.0,etc.)
              | AddrSpecIP4Bits String Int -- ^Accept this IP address and CIDR
                -- mask (/24,etc.)
              | AddrSpecIP6     String -- ^Accept this specific IP6 address.
              | AddrSpecIP6Bits String Int -- ^Accept this subnet and CIDR
                -- mask.
 deriving (Eq, Show)


