module TLS.Negotiation(
         TLSClientOptions(..)
       , defaultClientOptions
       , TLSServerOptions(..)
       , clientNegotiate
       , serverNegotiate
       )
 where

import Codec.Crypto.RSA
import Control.Exception
import Control.Monad
import Crypto.Random
import Crypto.Random.DRBG
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Maybe
import Data.Tagged
import Data.X509 hiding (Certificate, HashSHA1)
import System.Entropy
import TLS.Certificate
import TLS.Certificate.ClientCertificateType
import TLS.CipherSuite
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.KeyExchangeAlgorithm
import TLS.CipherSuite.PRF
import TLS.CipherSuite.SignatureAlgorithm
import TLS.CompressionMethod
import TLS.Context.Explicit
import TLS.DiffieHellman
import TLS.Handshake.Certificate
import TLS.Handshake.CertificateRequest
import TLS.Handshake.CertificateVerify
import TLS.Handshake.ClientHello
import TLS.Handshake.ClientKeyExchange
import TLS.Handshake.Extension
import TLS.Handshake.Finished
import TLS.Handshake.ServerHello
import TLS.Handshake.ServerHelloDone
import TLS.Handshake.ServerKeyExchange
import TLS.ProtocolVersion
import TLS.Random
import TLS.Session

data TLSClientOptions = TLSClientOptions {
       acceptableCipherSuites    :: [CipherSuite]
     , acceptableCompressionAlgs :: [CompressionMethod]
     , anonymousKeyExchangeIsOK  :: Bool
     , clientCertificates        :: [ASN1Cert]
     , clientPrivateKey          :: PrivKey
     , validateServerCerts       :: Maybe [ASN1Cert] -> IO Bool
     }

defaultClientOptions :: TLSClientOptions
defaultClientOptions  = TLSClientOptions {
    acceptableCipherSuites    = [suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                                 suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256]
  , acceptableCompressionAlgs = [nullCompression]
  , anonymousKeyExchangeIsOK  = False
  , clientCertificates        = []
  , clientPrivateKey          = error "Private key needed but not available."
  , validateServerCerts       = \ _ -> return True
  }

data TLSServerOptions = TLSServerOptions {
       acceptableCAs            :: [DistinguishedName]
     , acceptableCertTypes      :: [ClientCertificateType]
     , acceptableSigAlgs        :: Maybe [(SignatureAlgorithm,HashAlgorithm)]
     , serverCertificates       :: [ASN1Cert]
     , serverChooseCipherSuite  :: [CipherSuite] -> Maybe CipherSuite
     , serverChooseCompression  :: [CompressionMethod]-> Maybe CompressionMethod
     , serverDiffieHellmanGroup :: DiffieHellmanGroup
     , serverPrivateKey         :: PrivKey
     , shouldAskForClientCert   :: Bool
     , validateClientCerts      :: [ASN1Cert] -> IO Bool
     }

clientNegotiate :: IOSystem -> TLSClientOptions -> IO TLSContext
clientNegotiate iosys tlsopt =
  do -- generate and send the ClientHello message
     g                 <- generateTempRandomGen
     (clientHello, g') <- generateClientHello g tlsopt
     c0                <- initialContext iosys
     c1                <- writeHandshake (startRecording c0) clientHello
     -- get the ServerHello
     (c2, serverHello) <- nextHandshakeRecord (c1 :: TLSContext) ()
     let cipherSuite   = shCipherSuite serverHello
         serverExts    = shExtensions serverHello
     unless (cipherSuite `elem` acceptableCipherSuites tlsopt) $
       fail "Server agreed on unacceptable cipher suite."
     unless (legalServerExtensions serverExts (chExtensions clientHello)) $
       fail "Server send incompatible extensions."
     -- if the cipher rewquires a certificate, we should get it.
     (c3, mServerCert) <- maybeGetHandshake c2 () :: IO (TLSContext, Maybe Certificate)
     unless (isJust mServerCert == cipherRequiresServerCert cipherSuite) $
       fail "Server sent unexpected certificate."
     let serverCerts = cCertificateList `fmap` mServerCert :: Maybe [ASN1Cert]
     certsValidate <- validateServerCerts tlsopt serverCerts
     unless certsValidate $ fail "Server certificates were unacceptable."
     let serverPublic = case cCertificateList `fmap` mServerCert of
                          Nothing -> error "No public key available. (1)"
                          Just [] -> error "No public key available. (2)"
                          Just (cert1:_) -> certificatePublicKey cert1
     -- unless we're in a weird situation, we should probably get a server
     -- key exchange message.
     (c4, mServerKeyExch) <- maybeGetHandshake c3 cipherSuite
     case mServerKeyExch of
       Nothing ->
         return ()
       Just (ServerKeyExchangeAnon _) ->
         do unless (cipherKeyExchangeAlgorithm cipherSuite == ExchDH_anon) $
              fail "Got anonymous key exchange with non-anonymous cipher."
            unless (anonymousKeyExchangeIsOK tlsopt) $
              fail "Got unallowed anonymous key exchange."
       Just (ServerKeyExchangeSigned ps hasha siga sig) ->
         do unless (cipherSignatureAlgorithm cipherSuite == siga) $
              fail "ServerKeyEx signature algorithm doesn't match cipher suite."
            unless (cipherSuiteAllowsHash cipherSuite hasha) $
              fail "ServerKeyEx hash algorithm doesn't match cipher suite."
            unless (extensionsAllow siga hasha (shExtensions serverHello)) $
              fail "Extensions don't allow signature or hash algorithm."
            let msg = BS.concat [runPut (putRandom (chRandom clientHello)),
                                 runPut (putRandom (shRandom serverHello)),
                                 runPut (putServerDHParams ps)]
            unless (signatureValidates hasha siga serverPublic msg sig) $
              fail "Invalid key exchange signature."
     -- we may get a certificate request for ourselves
     (c5, mcr) <- maybeGetHandshake c4 (shServerVersion serverHello)
                    :: IO (TLSContext, Maybe CertificateRequest)
     when (isJust mcr && cipherKeyExchangeAlgorithm cipherSuite == ExchDH_anon)$
       fail "Anonmous server requested client certificate."
     -- but we should always get a ServerHelloDone
     (c6, _) <- nextHandshakeRecord c5 () :: IO (TLSContext, ServerHelloDone)
     -- Our turn. If we got a certificate request, we should send it.
     c7 <- if isJust mcr
            then let c = Certificate{cCertificateList=clientCertificates tlsopt}
                 in writeHandshake c6 c
            else return c6
     -- Write the client key exchange information.
     let sParams = maybe (error "ServerDHParams required but not available.")
                         skeParams mServerKeyExch
     (clientKeyExch, preMasterSecret, _) <-
            computePreMasterSecret g' sParams cipherSuite serverPublic
     c8 <- writeHandshake c7 clientKeyExch
     -- send a verification of our claimed certificated, if required.
     c9 <- if cipherRequiresClientCertVerification cipherSuite
             then let msgs    = emitRecording c8
                      siga    = cipherSignatureAlgorithm cipherSuite
                      hasha   = cipherHashAlgorithm cipherSuite
                      privkey = clientPrivateKey tlsopt
                      cver    = generateCertVerify siga hasha privkey msgs
                  in writeHandshake c8 cver
             else return c8
     -- Compute the master secret
     let masterSecretInf = prf preMasterSecret "master secret" $ runPut $ do
                             putRandom (chRandom clientHello)
                             putRandom (shRandom serverHello)
         masterSecret    = BS.take 48 masterSecretInf
         keyBlock        = prf masterSecret "key expansion" $ runPut $ do
                             putRandom (shRandom serverHello)
                             putRandom (chRandom clientHello)
         (cMAC, sMAC, cWrite, sWrite, cIV, sIV)
                         = runGet (getKeyMaterial cipherSuite) keyBlock
         encryptor       = cipherEncryptor cipherSuite cMAC sMAC
                                           cWrite sWrite cIV sIV
         compressor      = getCompressor (shCompressionMethod serverHello)
     let c10 = setNextCipherSuite c9 compressor encryptor
         cHandshakeMessages = emitRecording c10
         handshakeHash = sha256' cHandshakeMessages
         cVerifyDataInf = prf masterSecret "client finished" handshakeHash
         verifyDataLen = cipherVerifyDataLength cipherSuite
         cVerifyData = BS.take verifyDataLen cVerifyDataInf
     c11 <- sendChangeCipherSpec c10
     c12 <- writeHandshake c11 (Finished cVerifyData)
     c13 <- receiveChangeCipherSpec c12
     let sHandshakeMessages = emitRecording c13
         handshakeHash'     = sha256' sHandshakeMessages
         sVerifyDataInf     = prf masterSecret "server finished" handshakeHash'
         sVerifyData        = BS.take verifyDataLen sVerifyDataInf
     (c14, Finished sVerifyData') <- nextHandshakeRecord c13 ()
     unless (sVerifyData == sVerifyData') $
       fail "Final verification check failed."
     return (endRecording c14)

serverNegotiate :: IOSystem -> TLSServerOptions -> IO TLSContext
serverNegotiate iosys opts =
  do g0                <- generateTempRandomGen
     c0                <- startRecording `fmap` initialContext iosys
     -- get the ClientHello
     (c1, cHello) <- nextHandshakeRecord c0 ()
     unless (chSessionID cHello == EmptySession) $
       fail "FIXME: Library doesn't support session restarts."
     unless (chClientVersion cHello == versionTLS1_2) $
       fail "FIXME: Client wants too early a TLS version."
     let clientRand = chRandom cHello
     -- get the various pieces of information we need and generate the
     -- ServerHello.
     mrand <- generateRandom g0
     (serverRand, g1) <- case mrand of
                           Left err -> throw err
                           Right (a, b) -> return (a, b)
     let mnewSession = generateSession g1
     (newSession, g2) <- case mnewSession of
                           Left err -> throw err
                           Right (a, b) -> return (a, b)
     let clientCiphers = chCipherSuites cHello
     cipherSuite <- case serverChooseCipherSuite opts clientCiphers  of
                      Nothing -> -- FIXME: make this cleaner
                        fail "No agreeable cipher suite."
                      Just x ->
                        return x
     let clientComprs = chCompressionMethods cHello
     comprAlg <- case serverChooseCompression opts clientComprs of
                   Nothing -> -- FIXME: make this cleaner
                     fail "No agreeable compression method."
                   Just x ->
                     return x
     let sHello = ServerHello {
                    shServerVersion     = versionTLS1_2
                  , shRandom            = serverRand
                  , shSessionID         = newSession
                  , shCipherSuite       = cipherSuite
                  , shCompressionMethod = comprAlg
                  , shExtensions        = []
                  }
     c2 <- writeHandshake c1 sHello
     c3 <- if cipherRequiresServerCert cipherSuite
              then writeHandshake c2 (Certificate (serverCertificates opts))
              else return c2
     (c4, _, a) <- maybeSendServerKeyEx c3 g2 cipherSuite opts
                                        clientRand serverRand
     c5 <- if shouldRequestCertificate cipherSuite opts
              then writeHandshake c4 CertificateRequest {
                     crCertificateTypes = acceptableCertTypes opts
                   , crSupportedSignatureAlgorithms = acceptableSigAlgs opts
                   , crCertificateAuthorities = acceptableCAs opts
                   }
              else return c4
     c6 <- writeHandshake c5 ServerHelloDone
     (c7, clientPubKey) <- if shouldRequestCertificate cipherSuite opts
                             then readValidateClientCertificate c6 opts
                             else return (c6, error "No public key for client.")
     (c8,cke) <- nextHandshakeRecord c7 (cipherKeyExchangeAlgorithm cipherSuite)
     preMaster <- computeServerPreMasterSecret cipherSuite a cke opts 
     c9 <- if (shouldRequestCertificate cipherSuite opts) &&
              cipherRequiresClientCertVerification cipherSuite
             then do (c', cv) <- nextHandshakeRecord c8 ()
                     let ok = signatureValidates (cvHashAlgorithm cv)
                                                  (cvSignatureAlgorithm cv)
                                                  clientPubKey
                                                  (emitRecording c8)
                                                  (cvSignature cv)
                     unless ok $ fail "Certificate validation failed!"
                     return c'
             else return c8
     let masterSecretInf = prf preMaster "master secret" $ runPut $ do
                             putRandom clientRand
                             putRandom serverRand
         masterSecret    = BS.take 48 masterSecretInf
         keyBlock        = prf masterSecret "key expansion" $ runPut $ do
                             putRandom serverRand
                             putRandom clientRand
         (cMAC, sMAC, cWrite, sWrite, cIV, sIV)
                         = runGet (getKeyMaterial cipherSuite) keyBlock
         encryptor       = cipherEncryptor cipherSuite sMAC cMAC
                                           sWrite cWrite sIV cIV
         compressor      = getCompressor comprAlg
         c10             = setNextCipherSuite c9 compressor encryptor
     c11 <- receiveChangeCipherSpec c10
     (c12, Finished cVerifyData') <- nextHandshakeRecord c11 ()
     let verifyDataLen      = cipherVerifyDataLength cipherSuite
         cHandshakeMessages = emitRecording c11
         cHandshakeHash     = sha256' cHandshakeMessages
         cVerifyDataInf     = prf masterSecret "client finished" cHandshakeHash
         cVerifyData        = BS.take verifyDataLen cVerifyDataInf
     unless (cVerifyData == cVerifyData') $
       fail "Final verification check failed."
     c13 <- sendChangeCipherSpec c12
     let sHandshakeMessages = emitRecording c12
         sHandshakeHash     = sha256' sHandshakeMessages
         sVerifyDataInf     = prf masterSecret "server finished" sHandshakeHash
         sVerifyData        = BS.take verifyDataLen sVerifyDataInf
     c14 <- writeHandshake c13 (Finished sVerifyData)
     return (endRecording c14)

maybeSendServerKeyEx :: CryptoRandomGen g =>
                        TLSContext -> g -> CipherSuite -> TLSServerOptions ->
                        Random -> Random ->
                        IO (TLSContext, g, Integer)
maybeSendServerKeyEx c g cipherSuite opts clientRandom serverRandom =
  case cipherKeyExchangeAlgorithm cipherSuite of
    ExchDHE_DSS ->
      do c' <- writeHandshake c ske
         return (c', g', a)
    ExchDHE_RSA ->
      do c' <- writeHandshake c ske
         return (c', g', a)
    ExchDH_anon ->
      do c' <- writeHandshake c (ServerKeyExchangeAnon dhParams)
         return (c', g', a)
    ExchRSA     -> return (c, g, error "No legit DH private value for suite.")
    ExchDH_DSS  -> return (c, g, error "No legit DH private value for suite.")
    ExchDH_RSA  -> return (c, g, error "No legit DH private value for suite.")
    ExchNull    -> return (c, g, error "No legit DH private value for suite.")
 where
  hashAlg = cipherHashAlgorithm cipherSuite
  sigAlg  = cipherSignatureAlgorithm cipherSuite
  group   = serverDiffieHellmanGroup opts
  --
  ske = ServerKeyExchangeSigned dhParams hashAlg sigAlg sig
  sig = computeSignature hashAlg sigAlg (serverPrivateKey opts) msg
  msg = runPut $ do putRandom clientRandom
                    putRandom serverRandom
                    putServerDHParams dhParams
  --
  (a, dhParams, g') =
    case generateLocal group g of
      Left err      -> throw err
      Right (privA, g2) ->
        let pubA = computePublicValue group privA
        in (privA, groupToServerDHParams group pubA, g2)

generateTempRandomGen :: IO HashDRBG
generateTempRandomGen =
  do let taggedSeedLen = genSeedLength :: Tagged HashDRBG ByteLength
         seedLen       = unTagged taggedSeedLen
     seed <- getEntropy seedLen
     case newGen seed of
       Left  err -> throw err
       Right g   -> return g

generateClientHello :: HashDRBG -> TLSClientOptions -> IO (ClientHello, HashDRBG)
generateClientHello g tlsopt =
  do mrand <- generateRandom g
     case mrand of
       Left  err          -> throw err
       Right (myrand, g') ->
         let v = ClientHello {
                   chClientVersion      = versionTLS1_2
                 , chRandom             = myrand
                 , chSessionID          = EmptySession
                 , chCipherSuites       = acceptableCipherSuites tlsopt
                 , chCompressionMethods = acceptableCompressionAlgs tlsopt
                 , chExtensions         = []
                 }
          in return (v, g')

computePreMasterSecret :: CryptoRandomGen g =>
                          g -> ServerDHParams -> CipherSuite -> PubKey ->
                          IO (ClientKeyExchange, ByteString, g)
computePreMasterSecret g sparams cipherSuite serverPubKey'
  | isExplicitDiffieHellman cipherSuite =
      do let (group, pubs) = serverDHParamsToGroup sparams
         case generateLocal group g of
           Left err -> fail ("Couldn't generate local DH value: " ++ show err)
           Right (privc, g') ->
             do let pubcI = computePublicValue group privc
                    pubc = BS.dropWhile (== 0) (i2osp pubcI (dhgSize group))
                    premaster = computeSharedSecret group pubs privc
                return (ClientKeyExchangeDHExplicit pubc, premaster, g') 
  | isImplicitDiffieHellman cipherSuite =
      fail "Implicit DiffieHellman not currently supported."
  | cipherKeyExchangeAlgorithm cipherSuite == ExchRSA =
      case genBytes 46 g of
        Left err -> fail (show err)
        Right (random, g') ->
          do let PubKeyRSA serverPubKey = serverPubKey'
                 premaster = runPut $ do putProtocolVersion versionTLS1_2
                                         putByteString random
                 (encPreMaster, g'') = encryptPKCS g' serverPubKey premaster
             return (ClientKeyExchangeEncrypt encPreMaster, premaster, g'')
  | otherwise =
      fail "Sorry, don't know how to compute master secret for cipher."

isExplicitDiffieHellman :: CipherSuite -> Bool
isExplicitDiffieHellman cs =
  cipherKeyExchangeAlgorithm cs `elem` [ExchDH_anon,ExchDHE_DSS,ExchDHE_RSA]

isImplicitDiffieHellman :: CipherSuite -> Bool
isImplicitDiffieHellman cs =
  cipherKeyExchangeAlgorithm cs `elem` [ExchDHE_DSS,ExchDHE_RSA]

computeServerPreMasterSecret :: CipherSuite ->
                                Integer ->
                                ClientKeyExchange ->
                                TLSServerOptions ->
                                IO ByteString
computeServerPreMasterSecret cipherSuite privS cke opts =
  case cke of
    ClientKeyExchangeEncrypt bstr ->
      do unless (cipherKeyExchangeAlgorithm cipherSuite == ExchRSA) $
           fail "Got RSA client key exchange w/ non-RSA cipher."
         case serverPrivateKey opts of
           PrivKeyRSA key ->
             do let premaster = decryptPKCS key bstr
                unless (BS.length premaster == 48) $
                  fail "Incorrect size for encrypted pre-master key."
                return premaster
           PrivKeyDSA _ ->
             fail "DSA decryption not supported."
    ClientKeyExchangeDHImplicit ->
      do unless (isImplicitDiffieHellman cipherSuite) $
           fail "Non-explicit / explicit mismatch."
         fail "Implicit Diffie-Hellman is not currently supported."
    ClientKeyExchangeDHExplicit pubCBS ->
      do unless (isExplicitDiffieHellman cipherSuite) $
           fail "Explicit / non-explicit mismatch."
         let group = serverDiffieHellmanGroup opts
             pubC  = os2ip pubCBS
         return (computeSharedSecret group pubC privS)

cipherRequiresClientCertVerification :: CipherSuite -> Bool
cipherRequiresClientCertVerification cs =
  cipherKeyExchangeAlgorithm cs `elem` [ExchDHE_DSS, ExchDHE_RSA, ExchRSA]

signatureValidates :: HashAlgorithm -> SignatureAlgorithm ->
                      PubKey -> ByteString -> ByteString ->
                      Bool
signatureValidates hashalg SigRSA (PubKeyRSA rsakey) datum sig =
  rsassa_pkcs1_v1_5_verify (hashAlgToHashInfo hashalg) rsakey datum sig
signatureValidates _       SigDSA (PubKeyDSA _) _ _ =
  error "DSA not yet supported."
signatureValidates _       SigECDSA (PubKeyECDSA _ _) _ _ =
  error "ECDSA not yet supported."
signatureValidates _       SigAnonymous  _ _ _ =
  error "Trying to validate anonymous signature."
signatureValidates _ _ _ _ _ =
  error "Signature type does not match key type."

computeSignature :: HashAlgorithm -> SignatureAlgorithm ->
                    PrivKey -> ByteString ->
                    ByteString
computeSignature hashalg SigRSA (PrivKeyRSA rsakey) datum =
  rsassa_pkcs1_v1_5_sign (hashAlgToHashInfo hashalg) rsakey datum
computeSignature _       SigDSA (PrivKeyDSA _) _ =
  error "DSA not yet supported."
computeSignature _       SigAnonymous  _ _ =
  error "Trying to validate anonymous signature."
computeSignature _ _ _ _ =
  error "Signature type does not match key type."

cipherSuiteAllowsHash :: CipherSuite -> HashAlgorithm -> Bool
cipherSuiteAllowsHash cs hash =
  case cipherSignatureAlgorithm cs of
    SigAnonymous -> False
    SigRSA       -> True
    SigDSA       -> hash == HashSHA1
    SigECDSA     -> True -- FIXME: Not sure this works.

getKeyMaterial :: CipherSuite -> Get (ByteString, ByteString,
                                      ByteString, ByteString,
                                      ByteString, ByteString)
getKeyMaterial cs =
  do cMAC   <- getLazyByteString (cipherMACKeyLength cs)
     sMAC   <- getLazyByteString (cipherMACKeyLength cs)
     cWrite <- getLazyByteString (cipherEncryptionKeyLength cs)
     sWrite <- getLazyByteString (cipherEncryptionKeyLength cs)
     cIV    <- getLazyByteString (fromIntegral (cipherIVLength cs))
     sIV    <- getLazyByteString (fromIntegral (cipherIVLength cs))
     return (cMAC, sMAC, cWrite, sWrite, cIV, sIV)

shouldRequestCertificate :: CipherSuite -> TLSServerOptions -> Bool
shouldRequestCertificate suite opts =
  (cipherKeyExchangeAlgorithm suite /= ExchDH_anon) &&
  (shouldAskForClientCert opts)

readValidateClientCertificate :: TLSContext -> TLSServerOptions ->
                                 IO (TLSContext, PubKey)
readValidateClientCertificate c opts =
  do (c', ccerts) <- nextHandshakeRecord c ()
     case cCertificateList ccerts of
       [] ->
        fail "Received empty certificate list!"
       certs@(first:_) ->
         do res <- validateClientCerts opts certs
            unless res $
              fail "Client certificates failed validation."
            return (c', certificatePublicKey first)

sha256' :: ByteString -> ByteString
sha256' = bytestringDigest . sha256
