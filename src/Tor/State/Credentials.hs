-- |Credential management for a Tor node.
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.State.Credentials(
         Credentials
       , createCertificate
       , generateKeyPair
       , newCredentials
       , getSigningKey
       , getOnionKey
       , getNTorOnionKey
       , getTLSKey
       , getAddresses
       , getRouterDesc
       , addNewAddresses
       , isSignedBy
       )
 where

import Control.Concurrent
import Crypto.Error
import Crypto.Hash
import Crypto.Hash.Easy
import Crypto.PubKey.Curve25519 as Curve
import Crypto.PubKey.RSA as RSA
import Crypto.PubKey.RSA.KeyHash
import Crypto.PubKey.RSA.PKCS15
import Crypto.Random
import Data.ASN1.OID
import Data.ByteString(ByteString)
import Data.Hourglass
import Data.List.Compat(sortOn)
import Data.Map.Strict(Map,empty,insertWith,toList)
import Data.String
import Data.Word
import Data.X509
import Hexdump
import Prelude()
import Prelude.Compat
import System.Hourglass
import Tor.DataFormat.TorAddress
import Tor.Options
import Tor.RNG
import Tor.RouterDesc

-- |A snapshot of the current credential state for the system.
data CredentialState = CredentialState {
                         credRNG           :: TorRNG
                       , credStartTime     :: DateTime
                       , credNextSerialNum :: Integer
                       , credBaseDesc      :: RouterDesc
                       , credAddresses     :: Map TorAddress Int
                       , credIdentity      :: (SignedCertificate, PrivKey)
                       , credOnion         :: (SignedCertificate, PrivKey)
                       , credOnionNTor     :: (Curve.PublicKey,   SecretKey)
                       , credTLS           :: (SignedCertificate, PrivKey)
                       }

-- |The current credentials held by the node.
newtype Credentials = Credentials (MVar CredentialState)

-- |Generate new credentials fora fresh node.
newCredentials :: TorOptions -> IO Credentials
newCredentials opts =
  do g   <- drgNew
     now <- dateCurrent
     let s = generateState g opts now
     creds <- Credentials `fmap` newMVar s
     logMsg "Credentials created."
     logMsg ("  Signing key fingerprint: " ++ (showFingerprint (credIdentity s)))
     logMsg ("  Onion key fingerprint:   " ++ (showFingerprint (credOnion s)))
     logMsg ("  TLS key fingerprint:     " ++ (showFingerprint (credTLS s)))
     return creds
 where
  logMsg = torLog opts
  showFingerprint c =
    filter (/= ' ') (simpleHex (keyHash sha1 (signedObject (getSigned (fst c)))))

-- |Get the public signing certificate and its associated private key.
getSigningKey :: Credentials -> IO (SignedCertificate, PrivKey)
getSigningKey = getCredentials credIdentity

-- |Get the public onion certificate and its associated private key.
getOnionKey :: Credentials -> IO (SignedCertificate, PrivKey)
getOnionKey = getCredentials credOnion

-- |Get the public NTor Curve25519 public and private keys.
getNTorOnionKey :: Credentials -> IO (Curve.PublicKey, SecretKey)
getNTorOnionKey = getCredentials credOnionNTor

-- |Get the public TLS certificate and its associated private key.
getTLSKey :: Credentials -> IO (SignedCertificate, PrivKey)
getTLSKey = getCredentials credTLS

getCredentials :: (CredentialState -> a) -> Credentials -> IO a
getCredentials getter (Credentials stateMV) =
  do state  <- takeMVar stateMV
     now    <- dateCurrent
     let state' = updateKeys state now
     putMVar stateMV $! state'
     return (getter state')

-- |Get the current set of addresses we believe are associated with the node.
-- You should make sure to establish at least one outgoing link before calling
-- this.
getAddresses :: Credentials -> IO [TorAddress]
getAddresses (Credentials stateMV) =
  withMVar stateMV $ \ state ->
    return (orderList (credAddresses state))

-- |Get our own, current router decsription.
getRouterDesc :: Credentials -> IO RouterDesc
getRouterDesc (Credentials stateMV) =
  withMVar stateMV $ \ state ->
    do let port = routerORPort (credBaseDesc state)
           addrs = orderList (credAddresses state)
           (ip4addr, oaddrs) = splitAddresses port False addrs
           (onionCert, _) = credOnion state
           PubKeyRSA onionkey = certPubKey (signedObject (getSigned onionCert))
           (signCert, _) = credIdentity state
           PubKeyRSA signkey = certPubKey (signedObject (getSigned signCert))
           (ntorkey, _) = credOnionNTor state
       now <- dateCurrent
       return (credBaseDesc state) {
         routerIPv4Address = ip4addr
       , routerFingerprint = keyHash' sha1 signkey
       , routerUptime      = Just (fromIntegral (timeDiff (credStartTime state) now))
       , routerOnionKey    = onionkey
       , routerNTorOnionKey = Just ntorkey
       , routerSigningKey   = signkey
       , routerAlternateORAddresses = oaddrs
       }
 where
  splitAddresses :: Word16 -> Bool -> [TorAddress] -> (String, [(String, Word16)])
  splitAddresses _ False [] = ("127.0.0.1", [])
  splitAddresses _ True  [] = (error "Internal error (splitAddresses)", [])
  splitAddresses p False (IP4 x : rest) = (x, snd (splitAddresses p True rest))
  splitAddresses p state (x     : rest) =
    let (f, rest') = splitAddresses p state rest
    in case x of
         IP4 a -> (f, (a,p):rest')
         IP6 a -> (f, (a,p):rest')
         _     -> (f, rest')

-- |Add a new set of addresses that should be associated with our node.
addNewAddresses :: Credentials -> TorAddress -> IO [TorAddress]
addNewAddresses (Credentials stateMV) addr =
  modifyMVar stateMV $ \ state ->
    do let addrs' = insertWith (+) addr 1 (credAddresses state)
           state' = state{ credAddresses = addrs' }
       return (state', orderList addrs')

orderList :: Map TorAddress Int -> [TorAddress]
orderList x = reverse (map fst (sortOn snd (toList x)))

generateState :: TorRNG -> TorOptions -> DateTime -> CredentialState
generateState rng opts now = s3
 where
  s0      = CredentialState rng now 100 desc empty un un un un
  un      = undefined
  (s1, _) = maybeRegenId    True now s0
  (s2, _) = maybeRegenOnion True now s1
  (s3, _) = maybeRegenTLS   True now s2
  --
  desc    = blankRouterDesc {
    routerNickname                = maybe "" torNickname (torRelayOptions opts)
  , routerORPort                  = maybe 9001 torOnionPort (torRelayOptions opts)
  , routerPlatformName            = "Haskell"
  , routerEntryPublished          = timeFromElapsed (Elapsed (Seconds 0))
  , routerExitRules               = maybe [] torExitRules (torExitOptions opts)
  , routerIPv6Policy              = maybe (Left [PortSpecAll]) torIPv6Policy (torExitOptions opts)
  , routerContact                 = maybe Nothing torContact (torRelayOptions opts)
  , routerFamily                  = maybe [] torFamilies (torRelayOptions opts)
  , routerAllowSingleHopExits     = maybe False torAllowSingleHopExits (torExitOptions opts)
  }

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
  findKey rng =
    let (bytes, rng') = withRandomBytes rng 32 id
    in case toEither (secretKey (bytes :: ByteString)) of
         Left _        -> findKey rng'
         Right privkey -> (privkey, rng')
  (privntor, g'') = findKey g'
  pubntor = toPublic privntor
  toEither (CryptoPassed x) = Right x
  toEither (CryptoFailed e) = Left (show e)
  --
  state' = state{ credRNG = g'', credNextSerialNum = serial + 1
                , credOnion = (cert, PrivKeyRSA priv)
                , credOnionNTor = (pubntor, privntor)
                }

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

-- |Create a new certificate containing the public key and signed by the private
-- key, using the given serial number, CommonName, and validity period.
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

-- |Generate a new public/private RSA key pair of the given bit size.
generateKeyPair :: DRG g => g -> Int -> (RSA.PublicKey, PrivateKey, g)
generateKeyPair g bitSize = (pubKey, privKey, g')
 where
  ((pubKey, privKey), g') = withDRG g (generate (bitSize `div` 8) 65537)

-- |Return true if the first certificate is signed by the second.
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
