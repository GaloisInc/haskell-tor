module Test.Alert(alertTests) where

import Control.Applicative
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Alert

instance Arbitrary AlertLevel where
  arbitrary = elements [AlertWarning, AlertFatal]

instance Arbitrary AlertDescription where
  arbitrary = elements [AlertCloseNotify, AlertUnexpectedMessage,
                        AlertBadRecordMAC, AlertDecryptionFailedRESERVED,
                        AlertRecordOverflow, AlertDecompressionFailure,
                        AlertHandshakeFailure, AlertNoCertificateRESERVED,
                        AlertBadCertificate, AlertUnsupportedCertificate,
                        AlertCertificateRevoked, AlertCertificateExpired,
                        AlertCertificateUnknown, AlertIllegalParameter,
                        AlertUnknownCA, AlertAccessDenied, AlertDecodeError,
                        AlertDecryptError, AlertExportRestrictionRESERVED,
                        AlertProtocolVersion, AlertInsufficientSecurity,
                        AlertInternalError, AlertUserCanceled,
                        AlertNoRenegotiation, AlertUnsupportedExtension]

instance Arbitrary Alert where
  arbitrary = Alert <$> arbitrary <*> arbitrary

-- -----------------------------------------------------------------------------

prop_AlertLevelSerial :: AlertLevel -> Bool
prop_AlertLevelSerial = serialProp getAlertLevel putAlertLevel

prop_AlertDescSerial :: AlertDescription -> Bool
prop_AlertDescSerial = serialProp getAlertDescription putAlertDescription

prop_AlertSerial :: Alert -> Bool
prop_AlertSerial = serialProp getAlert putAlert

alertTests :: Test
alertTests =
  testGroup "Alerts" [
    testProperty "AlertLevel serializes" prop_AlertLevelSerial
  , testProperty "AlertDescription serializes" prop_AlertDescSerial
  , testProperty "Alerts serialize" prop_AlertSerial
  ]
