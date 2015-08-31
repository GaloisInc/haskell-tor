{-# LANGUAGE ImpredicativeTypes #-}
{-# LANGUAGE MultiWayIf         #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RecordWildCards    #-}
module Tor.State.Credentials(
         Credentials
       , createCertificate
       , generateKeyPair
       , newCredentials
       , getSigningKey
       , getOnionKey
       , getTLSKey
       , isSignedBy
       )
 where

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Crypto.Hash
import Crypto.Hash.Easy
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Crypto.Random
import Data.ASN1.OID
import Data.ByteString(ByteString)
import Data.Hourglass
import Data.Hourglass.Now
import Data.Monoid
import Data.String
import Data.Word
import Data.X509
import Hexdump
import Tor.RNG

data CredentialState = NextCheckAt DateTime | Regenerating
  deriving (Eq)

data Credentials = Credentials {
       tsCredentialState :: TVar CredentialState
     , tsNextSerialNum   :: TVar Word
     , tsIdentityCreds   :: TVar (SignedCertificate, PrivKey)
     , tsOnionCreds      :: TVar (SignedCertificate, PrivKey)
     , tsTLSCreds        :: TVar (SignedCertificate, PrivKey)
     }

newCredentials :: (String -> IO ()) -> IO Credentials
newCredentials logMsg =
  do g <- drgNew
     now <- getCurrentTime
     let (idc, onc, tlsc, checkAt, g') = regenerateAllKeys g now
     tsCredentialState <- newTVarIO (NextCheckAt checkAt)
     tsNextSerialNum   <- newTVarIO 105
     tsIdentityCreds   <- newTVarIO idc
     tsOnionCreds      <- newTVarIO onc
     tsTLSCreds        <- newTVarIO tlsc
     let creds = Credentials{..}
     logMsg "Credentials created."
     logMsg ("  Signing key fingerprint: " ++ (showFingerprint idc))
     logMsg ("  Onion key fingerprint:   " ++ (showFingerprint onc))
     logMsg ("  TLS key fingerprint:     " ++ (showFingerprint tlsc))
     _ <- forkIO (do sleepFor (timeDiff now checkAt)
                     runCredentialsCheck logMsg creds g')
     return creds
 where
  -- FIXME: probably should use a real fingerprint.
  showFingerprint c =
    filter (/= ' ') (simpleHex (sha1 (getSignedData (fst c))))

getSigningKey :: Credentials -> STM (SignedCertificate, PrivKey)
getSigningKey = readTVar . tsIdentityCreds

getOnionKey :: Credentials -> STM (SignedCertificate, PrivKey)
getOnionKey = getCredentials tsOnionCreds

getTLSKey :: Credentials -> STM (SignedCertificate, PrivKey)
getTLSKey = getCredentials tsTLSCreds

getCredentials :: (Credentials -> TVar (SignedCertificate, PrivKey)) ->
                  Credentials ->
                  STM (SignedCertificate, PrivKey)
getCredentials getter creds =
  do state <- readTVar (tsCredentialState creds)
     when (state == Regenerating) retry
     readTVar (getter creds)

runCredentialsCheck :: (String -> IO ()) -> Credentials -> TorRNG -> IO ()
runCredentialsCheck logMsg creds rng =
  do now <- getCurrentTime
     action <- atomically $
       do state <- readTVar (tsCredentialState creds)
          case state of
            Regenerating ->
              return (\ g -> do logMsg "ERROR: Regenerating in bad state."
                                sleepFor (mempty{ durationMinutes = 5 })
                                return g)
            NextCheckAt t | t <= now ->
              do writeTVar (tsCredentialState creds) Regenerating
                 return (updateCredentials now)
            NextCheckAt t ->
              return (\ g -> do sleepFor (timeDiff now t)
                                return g)
     rng' <- action rng
     runCredentialsCheck logMsg creds rng'
 where
  updateCredentials now g =
    do (msg, g') <- atomically (regenerateCertsFor creds now g)
       logMsg msg
       return g'

regenerateCertsFor :: Credentials -> DateTime -> TorRNG -> STM (String, TorRNG)
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
        | otherwise    -> return ("No cert regeneration required.", rng)
 where
  regenerateIdentityCert g =
    do let (idCred, onCred, tlsCred, checkAt, g') = regenerateAllKeys g now
       writeTVar (tsCredentialState st) (NextCheckAt checkAt)
       writeTVar (tsIdentityCreds st)   idCred
       writeTVar (tsOnionCreds st)      onCred
       writeTVar (tsTLSCreds st)        tlsCred
       writeTVar (tsNextSerialNum st)   105
       return ("Regenerated identity, onion, and TLS certificates.", g')
  --
  regenerateOnionCert g mint =
    do let endtime = now `timeAdd` mempty{ durationHours = 14 * 24 }
       (creds, g') <- freshCredentials g "haskell tor node" (now, endtime)
       writeTVar (tsOnionCreds st) creds
       let checkAt = (min endtime mint) `timeAdd` mempty{durationMinutes = -2}
       writeTVar (tsCredentialState st) (NextCheckAt checkAt)
       return ("Regenerated onion certificate.", g')
  regenerateTLSCert g mint =
    do let endtime = now `timeAdd` mempty{ durationHours = 2 }
       (creds, g') <- freshCredentials g "Tor TLS cert" (now, endtime)
       writeTVar (tsTLSCreds st) creds
       let checkAt = (min endtime mint) `timeAdd` mempty{durationMinutes = -2}
       writeTVar (tsCredentialState st) (NextCheckAt checkAt)
       return ("Regenerated TLS certificate.", g')
  --
  freshCredentials g name valids =
    do sNum        <- readTVar (tsNextSerialNum st)
       (_, idpriv) <- readTVar (tsIdentityCreds st)
       let (pub, priv, g') = generateKeyPair g 1024
           sNum' = fromIntegral sNum
           cert = createCertificate (PubKeyRSA pub) idpriv sNum' name valids
       writeTVar (tsNextSerialNum st) (sNum + 1)
       return ((cert, PrivKeyRSA priv), g')

regenerateAllKeys :: DRG g =>
                     g -> DateTime ->
                     ((SignedCertificate, PrivKey),
                      (SignedCertificate, PrivKey),
                      (SignedCertificate, PrivKey),
                      DateTime, g)
regenerateAllKeys g now = (idCreds, onionCreds, tlsCreds, checkAt, g''')
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
  twoYears  = now `timeAdd` mempty{ durationHours = (2 * 365 * 24) }
  twoWeeks  = now `timeAdd` mempty{ durationHours = (     14 * 24) }
  twoHours  = now `timeAdd` mempty{ durationHours = (           2) }
  checkAt   = now `timeAdd` mempty{ durationMinutes = -2 }

-- ----------------------------------------------------------------------------

createCertificate :: PubKey -> PrivKey ->
                     Integer -> String -> (DateTime, DateTime) ->
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
signMsg (PrivKeyRSA key) bstr = (sig, SignatureALG HashSHA1 PubKeyALG_RSA, ())
 where
  sig = errorLeft (sign Nothing (Just SHA1) key bstr)
  errorLeft (Left e)  = error ("Signing error: " ++ show e)
  errorLeft (Right x) = x
signMsg _                _     = error "Sign with non-RSA private key."

generateKeyPair :: DRG g => g -> Int -> (PublicKey, PrivateKey, g)
generateKeyPair g bitSize = (pubKey, privKey, g')
 where
  ((pubKey, privKey), g') = withDRG g (generate (bitSize `div` 8) 65537)

isSignedBy :: SignedCertificate -> Certificate -> Bool
isSignedBy cert bycert =
  case signedAlg (getSigned cert) of
    SignatureALG_Unknown _             -> False
    SignatureALG HashMD2 PubKeyALG_RSA -> False
    SignatureALG hashAlg PubKeyALG_RSA ->
      case certPubKey bycert of
        PubKeyRSA pubkey ->
          let sig     = signedSignature (getSigned cert)
              bstr    = getSignedData cert
              verify' = toVerify hashAlg
          in verify' pubkey bstr sig
        _ -> False
    SignatureALG _ _     -> False
 where
  toVerify HashSHA1   = verify (Just SHA1)
  toVerify HashSHA224 = verify (Just SHA224)
  toVerify HashSHA256 = verify (Just SHA256)
  toVerify HashSHA384 = verify (Just SHA384)
  toVerify HashSHA512 = verify (Just SHA512)
  toVerify _          = \ _ _ _ -> False


sleepFor :: TimeInterval t => t -> IO ()
sleepFor dur =
   do putStrLn ("Should sleepFor " ++ show secs ++ " seconds.")
      threadDelay (fromIntegral (toSeconds dur) * 1000000)
 where secs = fromIntegral (toSeconds dur) :: Integer
