module TLS.Alert(
         AlertLevel(..)
       , putAlertLevel
       , getAlertLevel
       , AlertDescription(..)
       , putAlertDescription
       , getAlertDescription
       , Alert(..)
       , putAlert
       , getAlert
       )
 where

import Control.Applicative
import Data.Binary.Get
import Data.Binary.Put


data AlertLevel = AlertWarning
                | AlertFatal
  deriving (Show, Eq)

putAlertLevel :: AlertLevel -> Put
putAlertLevel AlertWarning = putWord8 1
putAlertLevel AlertFatal   = putWord8 2

getAlertLevel :: Get AlertLevel
getAlertLevel =
  do b <- getWord8
     case b of
       1 -> return AlertWarning
       2 -> return AlertFatal
       _ -> fail "Illegal format for AlertLevel"

-- -----------------------------------------------------------------------------

data AlertDescription = AlertCloseNotify
                      | AlertUnexpectedMessage
                      | AlertBadRecordMAC
                      | AlertDecryptionFailedRESERVED
                      | AlertRecordOverflow
                      | AlertDecompressionFailure
                      | AlertHandshakeFailure
                      | AlertNoCertificateRESERVED
                      | AlertBadCertificate
                      | AlertUnsupportedCertificate
                      | AlertCertificateRevoked
                      | AlertCertificateExpired
                      | AlertCertificateUnknown
                      | AlertIllegalParameter
                      | AlertUnknownCA
                      | AlertAccessDenied
                      | AlertDecodeError
                      | AlertDecryptError
                      | AlertExportRestrictionRESERVED
                      | AlertProtocolVersion
                      | AlertInsufficientSecurity
                      | AlertInternalError
                      | AlertUserCanceled
                      | AlertNoRenegotiation
                      | AlertUnsupportedExtension
 deriving (Eq, Show)

putAlertDescription :: AlertDescription -> Put
putAlertDescription AlertCloseNotify               = putWord8 0
putAlertDescription AlertUnexpectedMessage         = putWord8 10
putAlertDescription AlertBadRecordMAC              = putWord8 20
putAlertDescription AlertDecryptionFailedRESERVED  = putWord8 21
putAlertDescription AlertRecordOverflow            = putWord8 22
putAlertDescription AlertDecompressionFailure      = putWord8 30
putAlertDescription AlertHandshakeFailure          = putWord8 40
putAlertDescription AlertNoCertificateRESERVED     = putWord8 41
putAlertDescription AlertBadCertificate            = putWord8 42
putAlertDescription AlertUnsupportedCertificate    = putWord8 43
putAlertDescription AlertCertificateRevoked        = putWord8 44
putAlertDescription AlertCertificateExpired        = putWord8 45
putAlertDescription AlertCertificateUnknown        = putWord8 46
putAlertDescription AlertIllegalParameter          = putWord8 47
putAlertDescription AlertUnknownCA                 = putWord8 48
putAlertDescription AlertAccessDenied              = putWord8 49
putAlertDescription AlertDecodeError               = putWord8 50
putAlertDescription AlertDecryptError              = putWord8 51
putAlertDescription AlertExportRestrictionRESERVED = putWord8 60
putAlertDescription AlertProtocolVersion           = putWord8 70
putAlertDescription AlertInsufficientSecurity      = putWord8 71
putAlertDescription AlertInternalError             = putWord8 80
putAlertDescription AlertUserCanceled              = putWord8 90
putAlertDescription AlertNoRenegotiation           = putWord8 100
putAlertDescription AlertUnsupportedExtension      = putWord8 110

getAlertDescription :: Get AlertDescription
getAlertDescription =
  do b <- getWord8
     case b of
       0   -> return AlertCloseNotify
       10  -> return AlertUnexpectedMessage
       20  -> return AlertBadRecordMAC
       21  -> return AlertDecryptionFailedRESERVED
       22  -> return AlertRecordOverflow
       30  -> return AlertDecompressionFailure
       40  -> return AlertHandshakeFailure
       41  -> return AlertNoCertificateRESERVED
       42  -> return AlertBadCertificate
       43  -> return AlertUnsupportedCertificate
       44  -> return AlertCertificateRevoked
       45  -> return AlertCertificateExpired
       46  -> return AlertCertificateUnknown
       47  -> return AlertIllegalParameter
       48  -> return AlertUnknownCA
       49  -> return AlertAccessDenied
       50  -> return AlertDecodeError
       51  -> return AlertDecryptError
       60  -> return AlertExportRestrictionRESERVED
       70  -> return AlertProtocolVersion
       71  -> return AlertInsufficientSecurity
       80  -> return AlertInternalError
       90  -> return AlertUserCanceled
       100 -> return AlertNoRenegotiation
       110 -> return AlertUnsupportedExtension
       _   -> fail "Unsupported value for AlertDescription"

-- -----------------------------------------------------------------------------

data Alert = Alert {
       alertLevel       :: AlertLevel
     , alertDescription :: AlertDescription
     }
 deriving (Eq, Show)

putAlert :: Alert -> Put
putAlert x =
  do putAlertLevel (alertLevel x)
     putAlertDescription (alertDescription x)

getAlert :: Get Alert
getAlert = Alert <$> getAlertLevel <*> getAlertDescription

