{-# LANGUAGE MultiWayIf #-}
module Tor.Link(
         TorLink
       , initializeClientTorLink
       , newRandomCircuit
       , modifyCircuitHandler
       , endCircuit
       , writeCell
       )
 where

import Codec.Crypto.RSA
import Control.Applicative
import Control.Concurrent
import Control.Concurrent.STM
import Control.Exception
import Control.Monad
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy(ByteString,toChunks)
import qualified Data.ByteString as SBS
import qualified Data.ByteString.Lazy as BS
import Data.ByteString.Lazy.Char8(pack)
import Data.Digest.Pure.SHA
import Data.Digest.Pure.SHA.HMAC
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.Word
import Data.X509
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.NetworkStack
import Tor.RouterDesc
import Tor.State
import Tor.State.Credentials
import TLS.Certificate
import TLS.CipherSuite
import TLS.CompressionMethod
import TLS.Context
import TLS.Negotiation

type CircuitHandler = TorCell -> IO ()

-- -----------------------------------------------------------------------------

data TorLink = TorLink {
       linkContext           :: TLSContext
     , linkInitiatedRemotely :: Bool
     , linkHandlerTable      :: TVar (Map Word32 CircuitHandler)
     }

newRandomCircuit :: CryptoRandomGen g =>
                    TorLink -> CircuitHandler -> g ->
                    STM (Word32, g)
newRandomCircuit link handler g =
  do let (bstr, g') = throwLeft (genBytes 4 g)
         v          = runGet getWord32host (BS.fromStrict bstr)
         -- FIXME: the below seems reverse of spec, but is what the code expects
         v' | linkInitiatedRemotely link = clearBit v 31
            | otherwise                  = setBit v 31
     curTable <- readTVar (linkHandlerTable link)
     if | v' == 0                -> newRandomCircuit link handler g'
        | Map.member v' curTable -> newRandomCircuit link handler g'
        | otherwise              ->
           do let table' = Map.insert v' handler curTable
              writeTVar (linkHandlerTable link) table'
              return (v', g')

modifyCircuitHandler :: TorLink -> Word32 -> CircuitHandler -> IO ()
modifyCircuitHandler link circId handler =
  atomically $ modifyTVar' (linkHandlerTable link) $ \ table ->
    Map.insert circId handler table

endCircuit :: TorLink -> Word32 -> IO ()
endCircuit link circId =
  atomically $ modifyTVar' (linkHandlerTable link) $ Map.delete circId

-- -----------------------------------------------------------------------------

-- |Create a direct link to the Tor node at the given address and port number.
-- Either returns the link or an error generated during the attempted
-- connection. Note that this routine performs some internal certificate
-- checking, but you should verify that the certificate you expected from
-- the connection is what you expected it to be.
initializeClientTorLink :: TorState ls s -> RouterDesc ->
                           IO (Either String TorLink)
initializeClientTorLink torst them =
  handle (\ e -> return (Left (show (e :: SomeException)))) $
    do now <- getCurrentTime
       let ns = getNetworkStack torst
           vlen = (now, (2 * 60 * 60) `addUTCTime` now)
       (idCert, idKey) <- getSigningCredentials torst
       (authPriv, authCert) <- withRNG torst (genCertificate idKey vlen)
       Just sock <- connect ns (routerIPv4Address them) (routerORPort them)
       tls <- clientNegotiate (toIOSystem ns sock) (clientTLSOpts authCert authPriv)
       let idCert'  = signedObject (getSigned idCert)
       -- send out our initial message
       let vers = putCell Versions
       writeTLS tls vers
       -- get their initial message
       (r2i, left, rLink, rCert, myAddr) <- getRespInitialMsgs tls
       addLocalAddress torst myAddr
       -- build and send the CERTS message
       let certs = putCell (Certs [RSA1024Identity idCert,
                                   RSA1024Authenticate authCert])
       writeTLS tls certs
       -- build and send the AUTHENTICATE message
       let i2r = vers `BS.append` certs
       hdr <- authMessageHeader tls idCert' rCert r2i i2r rLink
       mrand <- withRNG torst (genBytes' 24)
       rand <- case mrand of
                 Nothing -> fail "RNG failure."
                 Just x  -> return x
       let signedBit = hdr `BS.append` rand
           hash = sha256 signedBit
           sig = rsassa_pkcs1_v1_5_sign (HashInfo BS.empty id) authPriv hash
           msg = signedBit `BS.append` sig
       writeTLS tls $ putCell (Authenticate msg)
       -- finally, build and send the NETINFO message
       now' <- fromEnum <$> getPOSIXTime
       us <- getLocalAddresses torst
       let ni = NetInfo (fromIntegral now') (IP4 (routerIPv4Address them)) us
       writeTLS tls $ putCell ni
       -- ... and return the link pointer
       logMsg torst ("Created new link to " ++ routerIPv4Address them ++
                     if null (routerNickname them) then "" else
                      (" (" ++ show (routerNickname them) ++ ")"))
       handlerTableTV <- newTVarIO Map.empty
       _ <- forkIO (runLink torst tls handlerTableTV (toChunks left))
       return (Right (TorLink tls False handlerTableTV))

runLink :: TorState ls s ->
           TLSContext -> TVar (Map Word32 CircuitHandler) ->
           [SBS.ByteString] ->
           IO ()
runLink tor link handlerMapTV left =
  do mcell <- fetchCell (runGetIncremental getTorCell) left
     case mcell of
       Nothing -> return ()
       Just (cell, rest) ->
         do processCell cell
            runLink tor link handlerMapTV rest
 where
  fetchCell (Fail _ _ _)   _ = return Nothing
  fetchCell (Partial next) [] =
    do newbufs <- toChunks <$> readTLS link
       fetchCell (Partial next) newbufs
  fetchCell (Partial next) (f:rest) =
    fetchCell (next (Just f)) rest
  fetchCell (Done frest _ res) buf =
    return (Just (res, frest : buf))
  --
  processCell   Padding                       = return ()
  processCell   (Create _ _)                  = putStrLn "Implement incoming create!"
  processCell x@(Created circId _)            = sendToHandler circId x
  processCell x@(Relay circId _)              = sendToHandler circId x
  processCell x@(Destroy circId _)            = sendToHandler circId x
  processCell   (CreateFast _ _)              = putStrLn "Implement CreateFast"
  processCell x@(CreatedFast circId _ _)      = sendToHandler circId x
  processCell   (NetInfo _ _ _)               = return ()
  processCell x@(RelayEarly circId _)         = sendToHandler circId x
  processCell   (Create2 _ _ _)               = putStrLn "Implement Create2"
  processCell x@(Created2 circId _)           = sendToHandler circId x
  processCell   Versions                      = return ()
  processCell   (VPadding _)                  = return ()
  processCell   (Certs _)                     = return ()
  processCell   (AuthChallenge _ _)           = return ()
  processCell   (Authenticate _)              = return ()
  processCell   Authorize                     = return ()
  --
  sendToHandler circId x =
    do table <- readTVarIO handlerMapTV
       case Map.lookup circId table of
         Nothing ->
           logMsg tor ("Cell received for unknown circuit " ++ show circId)
         Just handler ->
           do _ <- forkIO (handler x)
              return ()

-- |Write the given cell to the Tor link.
writeCell :: TorLink -> TorCell -> IO ()
writeCell link cell =
  do let outputBS = putCell cell
     writeTLS (linkContext link) outputBS

-- -----------------------------------------------------------------------------

getRespInitialMsgs :: TLSContext ->
                      IO (ByteString, ByteString,
                          SignedCertificate, Certificate,
                          TorAddress)
getRespInitialMsgs tls =
  do cells <- getBaseCells baseDecodeStart BS.empty BS.empty
     let (bstr, left, Certs cs, AuthChallenge _ methods) = cells
     unless (1 `elem` methods) $ fail "No supported auth challenge method."
     linkCert <- exactlyOneLink cs Nothing
     tlsCerts <- getServerCertificates tls
     unless (linkCert `elem` tlsCerts) $ fail "Link certificated different?"
     let linkCert' = signedObject (getSigned linkCert)
     idCert   <- exactlyOneId cs Nothing
     let idCert' = signedObject (getSigned idCert)
     now      <- getCurrentTime
     when (certExpired linkCert' now) $ fail "Link certificate expired."
     when (certExpired idCert' now)   $ fail "Identity certificate expired."
     unless (is1024BitRSAKey linkCert) $ fail "Bad link certificate type."
     unless (is1024BitRSAKey idCert)   $ fail "Bad identity certificate type."
     unless (linkCert `isSignedBy` idCert') $ fail "Bad link cert signature."
     unless (idCert `isSignedBy` idCert') $ fail "Bad identity cert signature."
     -- OK, that stuff's good. We should be able to get the NetInfo cell now
     (left', NetInfo _ myAddr _) <- getNetInfoCellBit (netinfoDecodeStart left)
     return (bstr, BS.fromStrict left', linkCert, idCert', myAddr)
 where
  baseDecodeStart = runGetIncremental getResponderStart
  getBaseCells getter lastBS acc =
    case getter of
      Fail _ _ str     ->
        fail str
      Done _ i (a,b) ->
        do let (accchunk, leftover) = BS.splitAt i lastBS
           return (acc `BS.append` accchunk, leftover, a, b) 
      Partial next     ->
        do b <- readTLS tls
           putStrLn ("read " ++ show (BS.length b) ++ " bytes")
           let getter' = next (Just (BS.toStrict b))
           getBaseCells getter' b (acc `BS.append` lastBS)
  --
  netinfoDecodeStart l = 
    case runGetIncremental getNetInfoCell of
      f@(Fail _ _ _) -> f
      d@(Done _ _ _) -> d
      Partial next   -> next (Just (BS.toStrict l))
  getNetInfoCellBit getter =
    case getter of
      Fail _ _ str ->
        fail str
      Done leftover _ x ->
        return (leftover, x)
      Partial next ->
        do b <- readTLS tls
           let getter' = next (Just (BS.toStrict b))
           getNetInfoCellBit getter'
  --
  exactlyOneLink [] Nothing =
    fail "Not enough link certs."
  exactlyOneLink [] (Just x) =
    return x
  exactlyOneLink ((LinkKeyCert _):_) (Just _) =
    fail "Too many link certs."
  exactlyOneLink ((LinkKeyCert c):rest) Nothing =
    exactlyOneLink rest (Just c)
  exactlyOneLink (_:rest) acc =
    exactlyOneLink rest acc
  --
  exactlyOneId [] Nothing =
    fail "Not enough identity certs."
  exactlyOneId [] (Just x) =
    return x
  exactlyOneId ((RSA1024Identity _):_) (Just _) =
    fail "Too many identity certs."
  exactlyOneId ((RSA1024Identity c):rest) Nothing =
    exactlyOneId rest (Just c)
  exactlyOneId (_:rest) acc =
    exactlyOneId rest acc
  --
  is1024BitRSAKey cert =
    case certPubKey (signedObject (getSigned cert)) of
      PubKeyRSA pk -> public_size pk == 128
      _            -> False

getResponderStart :: Get (TorCell, TorCell)
getResponderStart =
  do _  <- getWord16be
     c  <- getWord8
     case c of
       132 -> -- AUTHORIZE; ignored
         do l <- fromIntegral <$> getWord16be
            _ <- getLazyByteString l
            getResponderStart
       128 -> -- VPADDING; ignored
         do l <- fromIntegral <$> getWord16be
            _ <- getLazyByteString l
            getResponderStart
       7   -> -- VERSIONS; yay!
         do l  <- fromIntegral <$> getWord16be
            vs <- replicateM (l `div` 2) getWord16be
            unless (4 `elem` vs) $ fail "Couldn't negotiate a common version."
            run Nothing Nothing
       _   -> -- something else; fail
         fail "Unacceptable initial cell from responder."
 where
  run (Just a) (Just b) = return (a, b)
  run ma       mb       =
    do cell <- getTorCell
       case cell of
         Padding           -> run ma mb
         VPadding _        -> run ma mb
         Certs _           -> run (Just cell) mb
         AuthChallenge _ _ -> run ma          (Just cell)
         _                 -> fail "Weird cell in initial response."

getNetInfoCell :: Get TorCell
getNetInfoCell =
  do cell <- getTorCell
     case cell of
       Padding           -> getNetInfoCell
       VPadding _        -> getNetInfoCell
       NetInfo _ _ _     -> return cell
       _                 -> fail "Unexpected cell in getNetInfoCell."

authMessageHeader :: TLSContext ->
                     Certificate -> Certificate ->
                     ByteString  -> ByteString  ->
                     SignedCertificate ->
                     IO ByteString
authMessageHeader tls iIdent rIdent r2i i2r rLink =
  do let atype  = pack "AUTH0001"
         cid    = keyHash sha256 iIdent
         sid    = keyHash sha256 rIdent
         slog   = sha256 r2i
         clog   = sha256 i2r
         scert  = sha256 (BS.fromStrict (encodeSignedObject rLink))
     clientRandom <- getClientRandom tls
     serverRandom <- getServerRandom tls
     masterSecret <- getMasterSecret tls
     let ccert      = pack "Tor V3 handshake TLS cross-certification\0"
         blob       = BS.concat [clientRandom, serverRandom, ccert]
         tlssecrets = hmacSha256 masterSecret blob
     return (BS.concat [atype, cid, sid, slog, clog, scert, tlssecrets])

genBytes' :: CryptoRandomGen g =>
             Int -> g ->
             (Maybe ByteString, g)
genBytes' x g =
  case genBytes x g of
    Left _          -> (Nothing, g)
    Right (res, g') -> (Just (BS.fromStrict res), g')

putCell :: TorCell -> ByteString
putCell = runPut . putTorCell

genCertificate :: CryptoRandomGen g =>
                  PrivKey -> (UTCTime, UTCTime) -> g ->
                  ((PrivateKey, SignedCertificate), g)
genCertificate signer valids g = ((priv, cert), g')
 where
  (pub, priv, g') = generateKeyPair g 1024
  cert            = createCertificate (PubKeyRSA pub) signer 998 "auth" valids

clientTLSOpts :: SignedCertificate -> PrivateKey -> TLSClientOptions
clientTLSOpts cert priv = TLSClientOptions {
    acceptableCipherSuites    = [suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                                 suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                 suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                 suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256]
  , acceptableCompressionAlgs = [nullCompression]
  , anonymousKeyExchangeIsOK  = False
  , clientCertificates        = [ASN1Cert cert]
  , clientPrivateKey          = PrivKeyRSA priv
  , validateServerCerts       = const (return True)
  }
