module Test.TorCell(torCellTests) where

import Control.Applicative
import Control.Monad
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.List
import Data.Word
import Numeric
import Test.Certificate()
import Test.QuickCheck
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.Standard
import Tor.DataFormat.TorCell

instance Arbitrary TorCell where
  arbitrary = oneof [
      return Padding
    , Create  <$> arbitrary <*> arbBSLen (128 + 16 + 42)
    , Created <$> arbitrary <*> arbBSLen (128 + 20)
    , Relay <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
            <*> arbitrary <*> arbBSLen (509 - 11)
    , Destroy <$> arbitrary <*> arbitrary
    , CreateFast <$> arbitrary <*> arbBSLen 20
    , CreatedFast <$> arbitrary <*> arbBSLen 20 <*> arbBSLen 20
    , NetInfo <$> arbitrary <*> arbitrary <*> arbitrary
    , RelayEarly <$> arbitrary
    , Create2 <$> arbitrary <*> arbitrary <*> (BS.pack <$> arbitrary)
    , Created2 <$> arbitrary <*> (BS.pack <$> arbitrary)
    , VPadding <$> (BS.pack <$> arbitrary)
    , Certs <$> arbitrary
    , AuthChallenge <$> arbBSLen 32 <*> arbitrary
    , Authenticate <$> (BS.pack <$> arbitrary)
    , return Authorize
    ]

instance Arbitrary RelayCommand where
  arbitrary = oneof [
      elements [ RelayBegin, RelayData, RelayEnd, RelayConnected, RelaySendMe
               , RelayExtend, RelayExtended, RelayTruncate, RelayTruncated
               , RelayDrop, RelayResolve, RelayResolved, RelayBeginDir
               , RelayExtend2, RelayExtended2, RelayEstablishIntro
               , RelayEstablishRendezvous, RelayIntroduce1, RelayIntroduce2
               , RelayRendezvous1, RelayRendezvous2, RelayIntroEstablished
               , RelayRendezvousEstablished, RelayIntroducedAck]
     , RelayCommandUnknown <$> (elements ([16..31]++[41..255]))
     ]

instance Arbitrary DestroyReason where
  arbitrary = oneof [
      elements [ NoReason, TorProtocolViolation, InternalError, RequestedDestroy
               , NodeHibernating, HitResourceLimit, ConnectionFailed
               , ORIdentityIssue, ORConnectionClosed, Finished
               , CircuitConstructionTimeout, CircuitDestroyed, NoSuchService
               ]
    , UnknownDestroyReason <$> (elements [13..255])
    ]

instance Arbitrary TorAddress where
  arbitrary = oneof [
      Hostname <$> arbitrary
    , IP4 . (intercalate "." . map show) <$> replicateM 4 (arbitrary :: Gen Word8)
    , IP6 . (intercalate ":" . map (\ x -> showHex x ""))
         <$> replicateM 8 (arbitrary :: Gen Word16)
    , return (TransientError "External transient error.")
    , return (NontransientError "External nontransient error.")
    ]

instance Arbitrary HandshakeType where
  arbitrary = oneof [
      return TAP
    , return Reserved
    , return NTor
    , Unknown <$> (elements [3..65535])
    ]

instance Arbitrary TorCert where
  arbitrary = oneof [
      LinkKeyCert <$> arbitrary
    , RSA1024Identity <$> arbitrary
    , RSA1024Authenticate <$> arbitrary
    ]

arbBSLen :: Int -> Gen ByteString
arbBSLen x = BS.pack <$> replicateM x arbitrary

prop_RelComSerializes :: RelayCommand -> Bool
prop_RelComSerializes = serialProp getRelayCommand putRelayCommand

prop_DestReasSerializes :: DestroyReason -> Bool
prop_DestReasSerializes = serialProp getDestroyReason putDestroyReason

prop_TorAddrSerializes :: TorAddress -> Bool
prop_TorAddrSerializes = serialProp getTorAddress putTorAddress

prop_HandshakeSerializes :: HandshakeType -> Bool
prop_HandshakeSerializes = serialProp getHandshakeType putHandshakeType

prop_TorCertSerializes :: TorCert -> Bool
prop_TorCertSerializes = serialProp getTorCert putTorCert

prop_TorCellSerializes :: TorCell -> Bool
prop_TorCellSerializes = serialProp getTorCell putTorCell

torCellTests :: Test
torCellTests =
  testGroup "TorCell Serialization" [
    testProperty "RelayCommand round-trips" prop_RelComSerializes
  , testProperty "DestroyReason round-trips" prop_DestReasSerializes
  , testProperty "TorAddress round-trips" prop_TorAddrSerializes
  , testProperty "HandshakeType round-trips" prop_HandshakeSerializes
  , testProperty "TorCert round-trips" prop_TorCertSerializes
  , testProperty "TorCell round-trips" prop_TorCellSerializes
  ]

