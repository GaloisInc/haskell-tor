{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
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
import Crypto.Hash
import Crypto.Hash.Easy
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Crypto.Random
import Data.ASN1.OID
import Data.ByteString(ByteString)
import Data.Hourglass
import Data.Hourglass.Now
import Data.String
import Data.X509
import Hexdump
import Tor.RNG

data CredentialState = CredentialState {
                         credRNG           :: TorRNG
                       , credNextSerialNum :: Integer
                       , credIdentity      :: (SignedCertificate, PrivKey)
                       , credOnion         :: (SignedCertificate, PrivKey)
                       , credTLS           :: (SignedCertificate, PrivKey)
                       }

newtype Credentials = Credentials (MVar CredentialState)

newCredentials :: (String -> IO ()) -> IO Credentials
newCredentials logMsg =
  do g   <- drgNew
     now <- getCurrentTime
     let s = generateState g now
     creds <- Credentials `fmap` newMVar s
     logMsg "Credentials created."
     logMsg ("  Signing key fingerprint: " ++ (showFingerprint (credIdentity s)))
     logMsg ("  Onion key fingerprint:   " ++ (showFingerprint (credOnion s)))
     logMsg ("  TLS key fingerprint:     " ++ (showFingerprint (credTLS s)))
     return creds
 where
  -- FIXME: probably should use a real fingerprint.
  showFingerprint c =
    filter (/= ' ') (simpleHex (sha1 (getSignedData (fst c))))

getSigningKey :: Credentials -> IO (SignedCertificate, PrivKey)
getSigningKey = getCredentials credIdentity

getOnionKey :: Credentials -> IO (SignedCertificate, PrivKey)
getOnionKey = getCredentials credOnion

getTLSKey :: Credentials -> IO (SignedCertificate, PrivKey)
getTLSKey = getCredentials credTLS

getCredentials :: (CredentialState -> (SignedCertificate, PrivKey)) ->
                  Credentials ->
                  IO (SignedCertificate, PrivKey)
getCredentials getter (Credentials stateMV) =
  do state  <- takeMVar stateMV
     now    <- getCurrentTime
     let state' = updateKeys state now
     putMVar stateMV $! state'
     return (getter state')

generateState :: TorRNG -> DateTime -> CredentialState
generateState rng now = s3
 where
  s0      = CredentialState rng 100 undefined undefined undefined
  (s1, _) = maybeRegenId    True now s0
  (s2, _) = maybeRegenOnion True now s1
  (s3, _) = maybeRegenTLS   True now s2

updateKeys :: CredentialState -> DateTime -> CredentialState
updateKeys s0 now = s3
 where
  (s1, forceOnion) = maybeRegenId    False      now s0
  (s2, forceTLS)   = maybeRegenOnion forceOnion now s1
  (s3, _)          = maybeRegenTLS   forceTLS   now s2

getCredCert :: (SignedCertificate, PrivKey) -> Certificate
getCredCert = signedObject . getSigned . fst

maybeRegenId :: Bool -> DateTime -> CredentialState -> (CredentialState, Bool)
maybeRegenId force now state | force || (now > expiration) = (state', True)
                             | otherwise                   = (state,  False)
 where
  (_, expiration) = certValidity (getCredCert (credIdentity state))
  --
  serial = credNextSerialNum state
  (pub, priv, g') = generateKeyPair (credRNG state) 1024
  cert = createCertificate (PubKeyRSA pub) (PrivKeyRSA priv) serial
                           "haskell tor" (now, twoYears)
  twoYears  = now `timeAdd` mempty{ durationHours = (2 * 365 * 24) }
  --
  state' = state{ credRNG = g', credNextSerialNum = serial + 1
                , credIdentity = (cert, PrivKeyRSA priv) }

maybeRegenOnion :: Bool -> DateTime -> CredentialState -> (CredentialState,Bool)
maybeRegenOnion force now state | force || (now > expiration) = (state', True)
                                | otherwise                   = (state,  False)
 where
  (_, expiration) = certValidity (getCredCert (credIdentity state))
  --
  serial = credNextSerialNum state
  (pub, priv, g') = generateKeyPair (credRNG state) 1024
  (_, idpriv) = credIdentity state
  cert = createCertificate (PubKeyRSA pub) idpriv serial
                           "haskell tor node" (now, twoWeeks)
  twoWeeks  = now `timeAdd` mempty{ durationHours = (14 * 24) }
  --
  state' = state{ credRNG = g', credNextSerialNum = serial + 1
                , credOnion = (cert, PrivKeyRSA priv) }

maybeRegenTLS :: Bool -> DateTime -> CredentialState -> (CredentialState,Bool)
maybeRegenTLS force now state | force || (now > expiration) = (state', True)
                                | otherwise                   = (state,  False)
 where
  (_, expiration) = certValidity (getCredCert (credIdentity state))
  --
  serial = credNextSerialNum state
  (pub, priv, g') = generateKeyPair (credRNG state) 1024
  (_, idpriv) = credIdentity state
  cert = createCertificate (PubKeyRSA pub) idpriv serial
                           "haskell tor node" (now, twoHours)
  twoHours  = now `timeAdd` mempty{ durationHours = 2 }
  --
  state' = state{ credRNG = g', credNextSerialNum = serial + 1
                , credTLS = (cert, PrivKeyRSA priv) }

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
