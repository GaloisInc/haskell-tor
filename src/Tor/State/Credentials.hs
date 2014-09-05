{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.State.Credentials(
         Credentials
       , createCertificate
       , newCredentials
       , getSigningKey
       , getOnionKey
       , getTLSKey
       )
 where

import Codec.Crypto.RSA
import Control.Concurrent.STM
import Crypto.Random.DRBG
import Data.ASN1.OID
import Data.ByteString.Lazy(fromStrict, toStrict)
import Data.ByteString(ByteString)
import Data.Digest.Pure.SHA
import Data.String
import Data.Time
import Data.Word
import Data.X509
import Tor.State.RNG

data CredentialState = NextCheckAt UTCTime | Regenerating

data Credentials = Credentials {
       tsCredentialState :: TVar CredentialState
     , tsNextSerialNum   :: TVar Word
     , tsIdentityCreds   :: TVar (SignedCertificate, PrivKey)
     , tsOnionCreds      :: TVar (SignedCertificate, PrivKey)
     , tsTLSCreds        :: TVar (SignedCertificate, PrivKey)
     }

newCredentials :: RNG -> (String -> IO ()) -> IO Credentials
newCredentials rng logMsg =
  do now <- getCurrentTime
     (idc, onc, tlsc, checkAt) <- withRNG rng (regenerateAllKeys now)
     tsCredentialState <- newTVarIO (NextCheckAt checkAt)
     tsNextSerialNum   <- newTVarIO 105
     tsIdentityCreds   <- newTVarIO idc
     tsOnionCreds      <- newTVarIO onc
     tsTLSCreds        <- newTVarIO tlsc
     logMsg "Credentials created."
     logMsg ("  Signing key fingerprint: " ++ (showFingerprint idc))
     logMsg ("  Onion key fingerprint:   " ++ (showFingerprint onc))
     logMsg ("  TLS key fingerprint:     " ++ (showFingerprint tlsc))
     return Credentials{..}
 where
  -- FIXME: probably should use a real fingerprint.
  showFingerprint c = show (sha1 (fromStrict (getSignedData (fst c))))

getSigningKey :: Credentials -> UTCTime ->
                 STM (SignedCertificate, PrivKey, Maybe (RNG -> STM String))
getSigningKey = getCredentials tsIdentityCreds

getOnionKey :: Credentials -> UTCTime ->
               STM (SignedCertificate, PrivKey, Maybe (RNG -> STM String))
getOnionKey = getCredentials tsOnionCreds

getTLSKey :: Credentials -> UTCTime ->
             STM (SignedCertificate, PrivKey, Maybe (RNG -> STM String))
getTLSKey = getCredentials tsTLSCreds

getCredentials :: (Credentials -> TVar (SignedCertificate, PrivKey)) ->
                  Credentials -> UTCTime ->
                  STM (SignedCertificate, PrivKey, Maybe (RNG -> STM String))
getCredentials getter st now =
  do certState <- readTVar (tsCredentialState st)
     case certState of
       NextCheckAt t | t <= now ->
         do writeTVar (tsCredentialState st) Regenerating
            let action = regenerateCertsFor st (addUTCTime (15 * 60) now)
            (cert, key) <- readTVar (getter st)
            return (cert, key, Just action)
       _ ->
         do (cert, key) <- readTVar (getter st)
            return (cert, key, Nothing)

regenerateCertsFor :: Credentials -> UTCTime -> RNG -> STM String
regenerateCertsFor st now rng =
  do (idcert, _) <- readTVar (tsIdentityCreds st)
     (oncert, _) <- readTVar (tsOnionCreds st)
     (tlcert, _) <- readTVar (tsTLSCreds st)
     let (_, idend) = certValidity (getCertificate idcert)
         (_, onend) = certValidity (getCertificate oncert)
         (_, tlend) = certValidity (getCertificate tlcert)
     if | idend <= now -> regenerateIdentityCert rng
        | onend <= now -> regenerateOnionCert    rng (min idend tlend)
        | tlend <= now -> regenerateTLSCert      rng (min idend onend)
 where
  regenerateIdentityCert rng' =
    withRNGSTM rng' $ \ g ->
     do let ((idCred, onCred, tlsCred, checkAt), g') = regenerateAllKeys now g
        writeTVar (tsCredentialState st) (NextCheckAt checkAt)
        writeTVar (tsIdentityCreds st)   idCred
        writeTVar (tsOnionCreds st)      onCred
        writeTVar (tsTLSCreds st)        tlsCred
        writeTVar (tsNextSerialNum st)   105
        return ("Regenerated identity, onion, and TLS certificates.", g')
  --
  regenerateOnionCert rng' mint =
    do let endtime = addUTCTime (14 * 24 * 60 * 60) now
       creds <- freshCredentials rng' "haskell tor node" (now, endtime)
       writeTVar (tsOnionCreds st) creds
       let checkAt = addUTCTime (-120) (min endtime mint)
       writeTVar (tsCredentialState st) (NextCheckAt checkAt)
       return "Regenerated onion certificate."
  regenerateTLSCert rng' mint =
    do let endtime = addUTCTime (2 * 60 * 60) now
       creds <- freshCredentials rng' "Tor TLS cert" (now, endtime)
       writeTVar (tsTLSCreds st) creds
       let checkAt = addUTCTime (-120) (min endtime mint)
       writeTVar (tsCredentialState st) (NextCheckAt checkAt)
       return "Regenerated TLS certificate."
  --
  freshCredentials rng' name valids =
    withRNGSTM rng' $ \ g ->
      do sNum        <- readTVar (tsNextSerialNum st)
         (_, idpriv) <- readTVar (tsIdentityCreds st)
         let (pub, priv, g') = generateKeyPair g 1024
             sNum' = fromIntegral sNum
             cert = createCertificate (PubKeyRSA pub) idpriv sNum' name valids
         writeTVar (tsNextSerialNum st) (sNum + 1)
         return ((cert, PrivKeyRSA priv), g')

regenerateAllKeys :: CryptoRandomGen g =>
                     UTCTime -> g ->
                     (((SignedCertificate, PrivKey),
                       (SignedCertificate, PrivKey),
                       (SignedCertificate, PrivKey),
                       UTCTime),
                      g)
regenerateAllKeys now g = ((idCreds, onionCreds, tlsCreds, checkAt), g''')
 where
  idCreds    = (identCert, PrivKeyRSA idPriv)
  onionCreds = (onionCert, PrivKeyRSA onionPriv)
  tlsCreds   = (tlsCert,   PrivKeyRSA tlsPriv)
  --
  (idPub,    idPriv,     g')   = generateKeyPair g   1024
  (onionPub, onionPriv,  g'')  = generateKeyPair g'  1024
  (tlsPub,   tlsPriv,    g''') = generateKeyPair g'' 1024
  identCert = createCertificate (PubKeyRSA idPub) (PrivKeyRSA idPriv)
                                101 "haskell tor" (now, twoYears)
  onionCert = createCertificate (PubKeyRSA onionPub) (PrivKeyRSA idPriv)
                                102 "haskell tor node" (now, twoWeeks)
  tlsCert   = createCertificate (PubKeyRSA tlsPub) (PrivKeyRSA idPriv)
                                103 "Tor TLS cert" (now, twoHours)
  --
  twoYears  = addUTCTime (2 * 365 * 24 * 60 * 60) now
  twoWeeks  = addUTCTime (     14 * 24 * 60 * 60) now
  twoHours  = addUTCTime (           2 * 60 * 60) now
  checkAt   = addUTCTime (-120) twoHours -- two minutes before

-- ----------------------------------------------------------------------------

createCertificate :: PubKey -> PrivKey ->
                     Integer -> String -> (UTCTime, UTCTime) ->
                     SignedExact Certificate
createCertificate certPubKey sigKey certSerial cName certValidity = signedCert
 where
  (signedCert, _)  = objectToSignedExact (signMsg sigKey) unsignedCert
  certSignatureAlg = SignatureALG HashSHA1 PubKeyALG_RSA
  unsignedCert     = Certificate{ .. }
  certVersion      = 3
  certExtensions   = Extensions Nothing
  certSubjectDN    = makeDN cName
  certIssuerDN     = makeDN "haskell"
  makeDN str       = DistinguishedName [
                       (getObjectID DnCommonName,       fromString str)
                     , (getObjectID DnCountry,          "US")
                     , (getObjectID DnOrganization,     "Haskell Community")
                     , (getObjectID DnOrganizationUnit, "cabal")
                     ]

signMsg :: PrivKey -> ByteString -> (ByteString, SignatureALG, ())
signMsg (PrivKeyRSA key) sbstr = (sig, SignatureALG HashSHA1 PubKeyALG_RSA, ())
 where
  sig  = toStrict sigL
  sigL = rsassa_pkcs1_v1_5_sign hashSHA1 key bstr
  bstr = fromStrict sbstr
signMsg _                _     = error "Sign with non-RSA private key."
