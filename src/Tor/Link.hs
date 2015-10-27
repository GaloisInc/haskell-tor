{-# LANGUAGE MultiWayIf #-}
module Tor.Link(
       -- * Routines using a link manager.
         LinkManager
       , initializeLinkManager
       , getLocalAddresses
       , getLink
       , setIncomingLinkHandler
       -- * Raw link data structures and routines
       , TorLink
       , initLink
       , linkInitiatedRemotely
       , linkRouterDesc
       , linkRead
       , linkWrite
       , linkClose
       )
 where

import Control.Concurrent
import Control.Exception
import Control.Monad
import Crypto.Hash(SHA256)
import Crypto.Hash.Easy
import Crypto.MAC.HMAC(hmac,HMAC)
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.KeyHash
import Crypto.PubKey.RSA.PKCS15
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteArray(convert)
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.ByteString.Char8(pack)
import Data.Hourglass
import Data.Hourglass.Now
import Data.IORef
import Data.Maybe
import Data.Tuple(swap)
import Data.Word
import Data.X509 hiding (HashSHA1, HashSHA256)
import Data.X509.CertificateStore
import Network.TLS hiding (Credentials)
import qualified Network.TLS as TLS
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.Link.CipherSuites
import Tor.Link.DH
import Tor.NetworkStack
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Credentials
import Tor.State.Routers

data HasBackend s => LinkManager ls s = LinkManager {
       lmNetworkStack        :: TorNetworkStack ls s
     , lmRouterDB            :: RouterDB
     , lmCredentials         :: Credentials
     , lmIdealLinks          :: Int
     , lmMaxLinks            :: Int
     , lmLog                 :: String -> IO ()
     , lmAddresses           :: MVar [TorAddress]
     , lmRNG                 :: MVar TorRNG
     , lmLinks               :: MVar [(RouterDesc, TorLink)]
     , lmIncomingLinkHandler :: MVar (TorLink -> IO ())
     }

initializeLinkManager :: HasBackend s =>
                         TorOptions ->
                         TorNetworkStack ls s ->
                         RouterDB -> Credentials ->
                         IO (LinkManager ls s)
initializeLinkManager o ns routerDB creds =
  do addrsMV   <- newMVar []
     rngMV     <- newMVar =<< drgNew
     linksMV   <- newMVar []
     ilHndlrMV <- newMVar (const (return ()))
     let lm = LinkManager {
                lmNetworkStack        = ns
              , lmRouterDB            = routerDB
              , lmCredentials         = creds
              , lmIdealLinks          = idealLinks
              , lmMaxLinks            = maxLinks
              , lmLog                 = torLog o
              , lmAddresses           = addrsMV
              , lmRNG                 = rngMV
              , lmLinks               = linksMV
              , lmIncomingLinkHandler = ilHndlrMV
              }
     when (isRelay || isExit) $
       do lsock <- listen ns orPort
          lmLog lm ("Waiting for Tor connections on port " ++ show orPort)
          _     <- forkIO $ forever $ do (sock, addr) <- accept ns lsock
                                         acceptIncoming lm sock addr
          return ()
     return lm
 where
  isRelay    = isJust (torRelayOptions o)
  isExit     = isJust (torExitOptions o)
  orPort     = maybe 9374 torOnionPort (torRelayOptions o)
  idealLinks = maybe 3 torTargetLinks (torEntranceOptions o)
  maxLinks   = maybe 3 torMaximumLinks (torRelayOptions o)

getLocalAddresses :: HasBackend s => LinkManager ls s -> IO [TorAddress]
getLocalAddresses = readMVar . lmAddresses

getLink :: HasBackend s => LinkManager ls s -> [RouterRestriction] -> IO TorLink
getLink lm restricts =
  modifyMVar (lmLinks lm) $ \ curLinks ->
    if length curLinks >= lmIdealLinks lm
       then getExistingLink curLinks []
       else buildNewLink    curLinks
 where
  getExistingLink :: [(RouterDesc, TorLink)] -> [(RouterDesc, TorLink)] ->
                     IO ([(RouterDesc, TorLink)], TorLink)
  getExistingLink []                 acc = buildNewLink acc
  getExistingLink (x@(rd,link):rest) acc
    | rd `meetsRestrictions` restricts   = return (rest ++ acc, link)
    | otherwise                          = getExistingLink rest (acc ++ [x])
  --
  buildNewLink :: [(RouterDesc, TorLink)] ->
                  IO ([(RouterDesc, TorLink)], TorLink)
  buildNewLink curLinks =
    do entranceDesc <- modifyMVar (lmRNG lm)
                         (getRouter (lmRouterDB lm) restricts)
       link         <- initLink (lmNetworkStack lm) (lmCredentials lm)
                         (lmRNG lm) (lmAddresses lm) (lmLog lm)
                         entranceDesc
       return (curLinks ++ [(entranceDesc, link)], link)

setIncomingLinkHandler :: HasBackend s =>
                          LinkManager ls s -> (TorLink -> IO ()) ->
                          IO ()
setIncomingLinkHandler lm h =
  modifyMVar_ (lmIncomingLinkHandler lm) (const (return h))

-- -----------------------------------------------------------------------------

data TorLink = TorLink {
       linkContext           :: Context
     , linkRouterDesc        :: Maybe RouterDesc
     , linkInitiatedRemotely :: Bool
     , linkReaderThread      :: ThreadId
     , linkReadBuffer        :: Chan TorCell
     }

-- |Read the next incoming cell from a link.
linkRead :: TorLink -> IO TorCell
linkRead = readChan . linkReadBuffer

-- |Write a cell to the link.
linkWrite :: TorLink -> TorCell -> IO ()
linkWrite link cell = sendData (linkContext link) (putCell cell)

-- |Close the link
linkClose :: TorLink -> IO ()
linkClose link =
  do killThread   (linkReaderThread link)
     bye          (linkContext link)
     contextClose (linkContext link)

-- |Create a direct link to the given tor node.  note that this routine performs
-- some internal certificate checking, but you should verify that the
-- certificate you expected from the connection is what you expected it to be.
-- YOU SHOULD PROBABLY NOT USE THIS ROUTINE. Instead, use getLink, above.
initLink :: HasBackend s =>
            TorNetworkStack ls s ->
            Credentials ->
            MVar TorRNG ->
            MVar [TorAddress] ->
            (String -> IO ()) ->
            RouterDesc ->
            IO TorLink
initLink ns creds rngMV myAddrsMV llog them =
  do now <- getCurrentTime
     let validity = (now, now `timeAdd` mempty{ durationHours = 2 })
     (idCert, idKey) <- getSigningKey creds
     (authPriv, authCert) <- modifyMVar rngMV
                               (return . genCertificate idKey validity)
     llog ("Trying to connect to " ++ (routerIPv4Address them))
     msock <- connect ns (routerIPv4Address them) (routerORPort them)
     case msock of
       Nothing ->
         throwIO (userError ("Could not create TLS connection to " ++
                              show (routerIPv4Address them) ++ ":" ++
                              show (routerORPort them)))
       Just sock ->
         do llog ("Just built connection with them.")
            let tcreds = TLS.Credentials [((CertificateChain [authCert,idCert]),
                                          PrivKeyRSA authPriv)]
            serverCertsIO <- newIORef (CertificateChain [])
            tls <- contextNew sock (clientTLSOpts "FIXME" tcreds serverCertsIO)
            handshake tls
            -- send out our initial message
            let vers = putCell Versions
            sendData tls vers
            -- get their initial message
            serverCerts <- readIORef serverCertsIO
            (r2i, left, rLink, rCert, myAddr) <- getRespInitialMsgs tls serverCerts
            myAddrs' <- modifyMVar myAddrsMV $ \ myAddrs ->
                          let myAddrs' | myAddr `elem` myAddrs = myAddrs
                                       | otherwise             = myAddr : myAddrs
                          in return (myAddrs', myAddrs')
            -- build and send the CERTS message
            let certs = putCell (Certs [RSA1024Identity idCert,
                                        RSA1024Auth authCert])
            sendData tls certs
            -- build and send the AUTHENTICATE message
            let i2r = BSL.toStrict (vers `BSL.append` certs)
                idCert' = signedObject (getSigned idCert)
            hdr <- authMessageHeader tls idCert' rCert r2i i2r rLink
            rand <- modifyMVar rngMV (return . swap . randomBytesGenerate 24)
            let signedBit = hdr `BS.append` rand
            Right sig <- signSafer noHash authPriv (sha256 signedBit)
            let msg = signedBit `BS.append` sig
            sendData tls $ putCell (Authenticate msg)
            -- finally, build and send the NETINFO message
            let ni = NetInfo (fromElapsed (timeGetElapsed now))
                             (IP4 (routerIPv4Address them)) myAddrs'
            sendData tls (putCell ni)
            -- ... and return the link pointer
            llog ("Created new link to " ++ routerIPv4Address them ++
                  if null (routerNickname them) then "" else
                     (" (" ++ show (routerNickname them) ++ ")"))
            bufCh <- newChan
            thr   <- forkIO (runLink llog bufCh tls [left])
            return (TorLink tls (Just them) False thr bufCh)

acceptIncoming :: HasBackend s => LinkManager ls s -> s -> TorAddress -> IO ()
acceptIncoming lm sock who =
 do now <- getCurrentTime
    let validity = (now, now `timeAdd` mempty{ durationHours = 2 })
    (idCert, idKey) <- getSigningKey (lmCredentials lm)
    let idCert' = signedObject (getSigned idCert)
    (linkPriv, linkCert) <- modifyMVar (lmRNG lm)
                              (return . genCertificate idKey validity)
    let creds = TLS.Credentials [(CertificateChain [linkCert, idCert],
                                  PrivKeyRSA linkPriv)]
    tls <- contextNew sock (serverTLSOpts creds)
    (versions, iversstr) <- getVersions tls
    unless (4 `elem` versions) $ fail "Link doesn't support version 4."
    -- "The responder sends a VERSIONS cell, ..."
    let versstr = putCell Versions
    sendData tls versstr
    -- "... a CERTS cell (4.2 below) to give the initiator the certificates
    -- it needs to learn the responder's identity, ..."
    let certsbstr = putCell (Certs [RSA1024Identity idCert,
                                    LinkKeyCert linkCert])

    sendData tls certsbstr
    -- "... an AUTH_CHALLENGE cell (4.3) that the initiator must include as
    -- part of its answer if it chooses to authenticate, ..."
    chalBStr <- modifyMVar (lmRNG lm) (return . swap . randomBytesGenerate 32)
    let authcbstr = putCell (AuthChallenge chalBStr [1])
    sendData tls authcbstr
    -- "... and a NETINFO cell (4.5) "
    others <- getLocalAddresses lm
    epochsec <- (fromElapsed . timeGetElapsed) <$> getCurrentTime
    sendData tls (putCell (NetInfo epochsec who others))
    -- "At this point the initiator may send a NETINFO cell if it does not
    -- wish to authenticate, or a CERTS cell, an AUTHENTICATE cell, and a
    -- NETINFO cell if it does."
    (iresp, leftOver) <- getInitiatorInfo tls
    case iresp of
      Left _ ->
        fail "Initiator chose not to authenticate."
      Right (Certs certs, Authenticate amsg, NetInfo _ _ _) ->
        do -- "To authenticate the initiator, the responder MUST check the
           -- following:
           --   * The CERTS cell contains exactly one CerType 3 'AUTH'
           --     certificate.
           let authCert  = exactlyOneAuth certs Nothing
               authCert' = signedObject (getSigned authCert)
           --   * The CERTS cell contains exactly one CerType 2 'ID'
           --     certificate
           let iidCert  = exactlyOneId certs Nothing
               iidCert' = signedObject (getSigned iidCert)
           --   * Both certificates have validAfter and validUntil dates
           --     that are not expired.
           when (certExpired authCert' now) $ fail "Auth certificate expired."
           when (certExpired iidCert' now)   $ fail "Id certificate expired."
           --   * The certified key in the AUTH certificate is a 1024-bit RSA
           --     key.
           unless (is1024BitRSAKey authCert) $
             fail "Auth certificate key is the wrong size."
           --   * The certified key in the ID certificate is a 1024-bit RSA
           --     key.
           unless (is1024BitRSAKey iidCert) $
             fail "Identity certificate key is the wrong size."
           --   * The auth certificate is correctly signed with the key in the
           --     ID certificate.
           unless (authCert `isSignedBy` iidCert') $
             fail "Auth certificate not signed by identity cert."
           --   * The ID certificate is correctly self-signed."
           unless (iidCert `isSignedBy` iidCert') $
             fail "Identity cert incorrectly self-signed."
           -- Checking these conditions is NOT sufficient to authenticate that
           -- the initiator has the ID it claims; to do so, the cells in 4.3
           -- [ACW: AUTH_CHALLENGE, send by us] and 4.4 [ACW: AUTHENTICATE,
           -- processed next] below must be exchanged." - tor-spec, Section 4.2
           -- If AuthType is 1 (meaning 'RSA-SHA256-TLSSecret'), then the
           -- Authentication contains the following:
           --   TYPE: The characters 'AUTH0001' [8 octets]
           let (auth0001, rest1) = BS.splitAt 8 amsg
           unless (auth0001 == (pack "AUTH0001")) $
             fail "Bad type in AUTHENTICATE cell."
           --   CID: A SHA256 hash of the initiator's RSA1024 identity key
           --        [32 octets]
           let (cid, rest2) = BS.splitAt 32 rest1
           unless (cid == keyHash sha256 iidCert') $
             fail "Bad initiator key hash in AUTHENTICATE cell."
           --   SID: A SHA256 hash of the responder's RSA1024 identity key
           --        [32 octets]
           let (sid, rest3) = BS.splitAt 32 rest2
           unless (sid == keyHash sha256 idCert') $
             fail "Bad responder key hash in AUTHENTICATE cell."
           --   SLOG: A SHA256 hash of all bytes sent from the responder to
           --         the initiator as part of the negotiation up to and
           --         including the AUTH_CHALLENGE cell; that is, the
           --         VERSIONS cell, the CERTS cell, the AUTH_CHALLENGE
           --         cell, and any padding cells. [32 octets]
           let (slog, rest4) = BS.splitAt 32 rest3
               r2i = BSL.concat [versstr, certsbstr, authcbstr]
           unless (slog == sha256 (BSL.toStrict r2i)) $
             fail "Bad hash of responder log in AUTHENTICATE cell."
           --  CLOG: A SHA256 hash of all bytes sent from the initiator to
           --        the responder as part of the negotiation so far; that is
           --        the VERSIONS cell and the CERTS cell and any padding
           --        cells. [32 octets]
           let (clog, rest5) = BS.splitAt 32 rest4
               i2r           = iversstr `BSL.append` putCell (Certs certs)
           unless (clog == sha256 (BSL.toStrict i2r)) $
             fail "Bad hash of initiator log in AUTHENTICATE cell."
           --  SCERT: A SHA256 hash of the responder's TLS link certificate.
           --         [32 octets]
           let (scert, rest6) = BS.splitAt 32 rest5
               linkCertBStr   = encodeSignedObject linkCert
           unless (scert == sha256 linkCertBStr) $
             fail "Bad hash of my link cert in AUTHENTICATE cell."
           --  TLSSECRETS: A SHA256 HMAC, using the TLS master secret as the
           --              secret key, of the following:
           --                - client_random, as sent in the TLS Client Hello
           --                - server_random, as sent in the TLS Server Hello
           --                - the NUL terminated ASCII string:
           --                 "Tor V3 handshake TLS cross-certificate"
           --              [32 octets]
           let (tlssecrets, rest7) = BS.splitAt 32 rest6
           ctxt <- nothingError <$> contextGetInformation tls
           let cRandom = unClientRandom (nothingError (infoClientRandom ctxt))
               sRandom = unServerRandom (nothingError (infoServerRandom ctxt))
               masterSecret = nothingError (infoMasterSecret ctxt)
           let ccert       = pack "Tor V3 handshake TLS cross-certification\0"
               blob        = BS.concat [cRandom, sRandom, ccert]
               tlssecrets' = convert (hmac masterSecret blob :: HMAC SHA256)
           unless (tlssecrets == tlssecrets') $
             fail "TLS secret mismatch in AUTHENTICATE cell."
           --  RAND: A 24 byte value, randomly chosen by the initiator
           let (rand, sig) = BS.splitAt 24 rest7
           --  SIG: A signature of a SHA256 hash of all the previous fields
           --       using the initiator's "Authenticate" key as presented.
           let msg = BS.concat [auth0001, cid, sid, slog, clog, scert,
                                tlssecrets, rand]
               hash = sha256 msg
               PubKeyRSA pub = certPubKey authCert'
               res = verify noHash pub hash sig
           unless res $
             fail "Signature verification failure in AUTHENITCATE cell."
           --
           bufCh <- newChan
           thr   <- forkIO (runLink (lmLog lm) bufCh tls [leftOver])
           desc  <- findRouter (lmRouterDB lm) cid
           let link = TorLink tls desc True thr bufCh
           linkHandler <- readMVar (lmIncomingLinkHandler lm)
           linkHandler link
           lmLog lm ("Incoming link created from " ++ show who)
           return ()
      Right (_, _, _) ->
        fail "Internal error getting initiator data."
 where
  nothingError :: Maybe a -> a
  nothingError Nothing  = error "Couldn't fetch TLS secrets."
  nothingError (Just x) = x

runLink :: (String -> IO ()) -> Chan TorCell ->
           Context -> [ByteString] ->
           IO ()
runLink llog rChan context initialBS =
  catch (run initialState initialBS) logException
 where
  logException :: SomeException -> IO ()
  logException e
    | Just ThreadKilled <- fromException e = return ()
    | otherwise = llog ("Exception raised running link: " ++ show e)
  --
  initialState = runGetIncremental getTorCell
  --
  run   (Fail    _    _ e)    _        = llog ("Error reading link: " ++ e)
  run x@(Partial _)           []       = recvData context >>= (\ b -> run x [b])
  run   (Partial next)        (f:rest) = run (next (Just f)) rest
  run   (Done    r1   _ x)    r2       = do writeChan rChan x
                                            run initialState (r1:r2)

-- -- -----------------------------------------------------------------------------
-- 
-- newRandomCircuit :: DRG g =>
--                     TorLink -> CircuitHandler -> g ->
--                     IO (Word32, g)
-- newRandomCircuit link handler g =
--   do let (bstr, g') = randomBytesGenerate 4 g
--          v          = runGet getWord32host (BSL.fromStrict bstr)
--          v' | linkInitiatedRemotely link = clearBit v 31
--             | otherwise                  = setBit v 31
--      curTable <- takeMVar (linkHandlerTable link)
--      if (v' == 0) || Map.member v' curTable
--         then do putMVar (linkHandlerTable link) curTable
--                 newRandomCircuit link handler g'
--         else do let table' = Map.insert v' handler curTable
--                 putMVar (linkHandlerTable link) table'
--                 return (v', g')

getVersions :: Context -> IO ([Word16], BSL.ByteString)
getVersions tls =
  do bstr <- BSL.fromStrict <$> recvData tls
     return (runGet getVersions' bstr, bstr)
 where
  getVersions' =
    do _   <- getWord16be
       cmd <- getWord8
       unless (cmd == 7) $ fail "Versions command /= 7"
       len <- getWord16be
       replicateM (fromIntegral len `div` 2) getWord16be

getInitiatorInfo :: Context ->
                    IO (Either TorCell (TorCell,TorCell,TorCell), ByteString)
getInitiatorInfo tls = getCells base
 where
  getCells (Fail _ _ str)  = fail str
  getCells (Done rest _ x) = return (x, rest)
  getCells (Partial f)     =
    do next <- recvData tls
       getCells (f (Just next))
  --
  base = runGetIncremental (run Nothing Nothing Nothing)
  --
  run (Just a) (Just b) (Just c) = return (Right (a, b, c))
  run ma       mb       mc       =
    do cell <- getTorCell
       case cell of
         Padding                                -> run ma mb mc
         VPadding _                             -> run ma mb mc
         NetInfo _ _ _
           | (ma == Nothing) && (mb == Nothing) -> return (Left cell)
           | otherwise                          -> run ma mb (Just cell)
         Certs _                                -> run (Just cell) mb mc
         Authenticate _                         -> run ma (Just cell) mc
         _                                      ->
           fail "Weird cell in initiator response."


-- -- -----------------------------------------------------------------------------

getRespInitialMsgs :: Context -> CertificateChain ->
                      IO (ByteString, ByteString,
                          SignedCertificate, Certificate,
                          TorAddress)
getRespInitialMsgs tls (CertificateChain tlsCerts) =
  do cells <- getBaseCells baseDecodeStart BS.empty BS.empty
     let (bstr, left, Certs cs, AuthChallenge _ methods) = cells
     unless (1 `elem` methods) $ fail "No supported auth challenge method."
     -- "To authenticate the responder, the initiator MUST check the following:
     --    * The CERTS cell contains exactly one CertType 1 'Link' certificate
     let linkCert  = exactlyOneLink cs Nothing
         linkCert' = signedObject (getSigned linkCert)
     --    * The CERTS cell contains exactly one CertType 2 'Id' certificate
     let idCert  = exactlyOneId cs Nothing
         idCert' = signedObject (getSigned idCert)
     --    * Both certificates have validAfter and validUntil dates that
     --      are not expired.
     now      <- getCurrentTime
     when (certExpired linkCert' now) $ fail "Link certificate expired."
     when (certExpired idCert' now)   $ fail "Identity certificate expired."
     --    * The certified key in the Link certificate matches the link key
     --      that was used to negotiate the TLS connection.
     unless (linkCert `elem` tlsCerts) $ fail "Link certificated different?"
     --    * The certified key in the ID certificate is a 1024-bit RSA key
     unless (is1024BitRSAKey idCert)   $ fail "Bad identity certificate type."
     --    * The certified key in the ID certificate was used to sign both
     --      certificates.
     --    * The link certificate is correctly signed with the key in the ID
     --      certificate.
     --    * The ID certificate is correctly self-signed.
     unless (linkCert `isSignedBy` idCert') $ fail "Bad link cert signature."
     unless (idCert `isSignedBy` idCert') $ fail "Bad identity cert signature."
     -- Checking these conditions is sufficient to authenticate that the
     -- initiator is talking to the Tor node with the expected identity, as
     -- certified in the ID certificate." -- tor-spec, 4.2
     (left', NetInfo _ myAddr _) <- getNetInfoCellBit (netinfoDecodeStart left)
     return (bstr, left', linkCert, idCert', myAddr)
 where
  baseDecodeStart = runGetIncremental getResponderStart
  getBaseCells getter lastBS acc =
    case getter of
      Fail _ _ str     ->
        fail str
      Done _ i (a,b) ->
        do let (accchunk, leftover) = BS.splitAt (fromIntegral i) lastBS
           return (acc `BS.append` accchunk, leftover, a, b)
      Partial next     ->
        do b <- recvData tls
           let getter' = next (Just b)
           getBaseCells getter' b (acc `BS.append` lastBS)
  --
  netinfoDecodeStart l = 
    case runGetIncremental getNetInfoCell of
      f@(Fail _ _ _) -> f
      d@(Done _ _ _) -> d
      Partial next   -> next (Just l)
  getNetInfoCellBit getter =
    case getter of
      Fail _ _ str ->
        fail str
      Done leftover _ x ->
        return (leftover, x)
      Partial next ->
        do b <- recvData tls
           let getter' = next (Just b)
           getNetInfoCellBit getter'

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

authMessageHeader :: Context ->
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
         scert  = sha256 (encodeSignedObject rLink)
     ctxt <- nothingError <$> contextGetInformation tls
     let cRandom = unClientRandom (nothingError (infoClientRandom ctxt))
         sRandom = unServerRandom (nothingError (infoServerRandom ctxt))
         masterSecret = nothingError (infoMasterSecret ctxt)
     let ccert      = pack "Tor V3 handshake TLS cross-certification\0"
         blob       = BS.concat [convert cRandom, convert sRandom, ccert]
         tlssecrets = convert (hmac masterSecret blob :: HMAC SHA256)
     return (BS.concat [atype, cid, sid, slog, clog, scert, tlssecrets])
 where
  nothingError Nothing  = error "Failure to generate authentication secrets."
  nothingError (Just a) = a

putCell :: TorCell -> BSL.ByteString
putCell = runPut . putTorCell

genCertificate :: DRG g =>
                  PrivKey -> (DateTime, DateTime) -> g ->
                  (g, (PrivateKey, SignedCertificate))
genCertificate signer valids g = (g', (priv, cert))
 where
  (pub, priv, g') = generateKeyPair g 1024
  cert            = createCertificate (PubKeyRSA pub) signer 998 "auth" valids

clientTLSOpts :: String -> TLS.Credentials ->
                 IORef CertificateChain ->
                 ClientParams
clientTLSOpts target creds ccio = ClientParams {
    clientUseMaxFragmentLength     = Nothing
  , clientServerIdentification     = (target, mempty)
  , clientUseServerNameIndication  = False
  , clientWantSessionResume        = Nothing
  , clientShared                   = Shared {
      sharedCredentials            = creds
    , sharedSessionManager         = noSessionManager
    , sharedCAStore                = makeCertificateStore []
    , sharedValidationCache        = exceptionValidationCache []
    }
  , clientHooks                    = ClientHooks {
      onCertificateRequest         = const (return (getRealCreds creds))
    , onNPNServerSuggest           = Nothing
    , onServerCertificate          = \ _ _ _ cc ->
                                       do writeIORef ccio cc
                                          return [] -- FIXME????
    , onSuggestALPN                = return Nothing
    }
  , clientSupported                = Supported {
      supportedVersions            = [TLS10,TLS11,TLS12]
    , supportedCiphers             = [suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                                      suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                      suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                      suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256]
    , supportedCompressions        = [nullCompression]
    , supportedHashSignatures      = [(HashSHA1,   SignatureRSA),
                                      (HashSHA256, SignatureRSA)]
    , supportedSecureRenegotiation = True
    , supportedSession             = False
    , supportedFallbackScsv        = True
    , supportedClientInitiatedRenegotiation = True
    }
  }
 where
  getRealCreds (TLS.Credentials [])    = Nothing
  getRealCreds (TLS.Credentials (a:_)) = Just a

serverTLSOpts :: TLS.Credentials -> ServerParams
serverTLSOpts creds = ServerParams {
    serverWantClientCert           = False
  , serverCACertificates           = signedCerts
  , serverDHEParams                = Just oakley2
  , serverShared                   = Shared {
      sharedCredentials            = creds
    , sharedSessionManager         = noSessionManager
    , sharedCAStore                = makeCertificateStore []
    , sharedValidationCache        = exceptionValidationCache []
    }
  , serverHooks                    = ServerHooks {
      onClientCertificate          = const (return CertificateUsageAccept) -- FIXME?
    , onUnverifiedClientCert       = return True -- FIXME?
    , onCipherChoosing             = chooseTorCipher
    , onSuggestNextProtocols       = return Nothing
    , onNewHandshake               = \ _ -> return True -- FIXME?
    , onALPNClientSuggest          = Nothing
    }
  , serverSupported                = Supported {
      supportedVersions            = [TLS12]
    , supportedCiphers             = [suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                                      suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                      suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                      suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256]
    , supportedCompressions        = [nullCompression]
    , supportedHashSignatures      = [(HashSHA1,   SignatureRSA),
                                      (HashSHA256, SignatureRSA)]
    , supportedSecureRenegotiation = True
    , supportedSession             = False
    , supportedFallbackScsv        = True
    , supportedClientInitiatedRenegotiation = True
    }
  }
 where
  TLS.Credentials innerCreds = creds
  certChains             = map fst innerCreds
  signedCerts            = concatMap (\ (CertificateChain x) -> x) certChains

chooseTorCipher :: Version -> [Cipher] -> Cipher
chooseTorCipher _ ciphers
  | ciphers `isEquivList` fixedCipherList =
       suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | isV2PlusCipherSet ciphers =
       suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA
  | otherwise =
       error "Unacceptable cipher list provided by client."

isEquivList :: Eq a => [a] -> [a] -> Bool
isEquivList xs ys = (length xs == length ys) && and (map (`elem` ys) xs)

isV2PlusCipherSet :: [Cipher] -> Bool
isV2PlusCipherSet suites = 
  -- FIXME: This is wrong, as the last test should be "and there's another
  -- one that isn't one of those three"
  (suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA  `elem` suites) &&
  (suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA  `elem` suites) &&
  (suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA `elem` suites) &&
  (length suites > 3)

fixedCipherList :: [Cipher]
fixedCipherList = [
    suiteTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
  , suiteTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA
  , suiteTLS_ECDH_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
  , suiteTLS_RSA_WITH_AES_256_CBC_SHA
  , suiteTLS_ECDHE_ECDSA_WITH_RC4_128_SHA
  , suiteTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
  , suiteTLS_ECDHE_RSA_WITH_RC4_128_SHA
  , suiteTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_DHE_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_DHE_DSS_WITH_AES_128_CBC_SHA
  , suiteTLS_ECDH_RSA_WITH_RC4_128_SHA
  , suiteTLS_ECDH_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_ECDH_ECDSA_WITH_RC4_128_SHA
  , suiteTLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
  , suiteTLS_RSA_WITH_RC4_128_MD5
  , suiteTLS_RSA_WITH_RC4_128_SHA
  , suiteTLS_RSA_WITH_AES_128_CBC_SHA
  , suiteTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
  , suiteSSL3_EDH_RSA_DES_192_CBC3_SHA
  , suiteSSL3_EDH_DSS_DES_192_CBC3_SHA
  , suiteTLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
  , suiteSSL3_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
  , suiteTLS_RSA_WITH_3DES_EDE_CBC_SHA
  ]

-- -----------------------------------------------------------------------------

exactlyOneLink :: [TorCert] -> Maybe SignedCertificate -> SignedCertificate
exactlyOneLink []                     Nothing  = error "Not enough link certs."
exactlyOneLink []                     (Just x) = x
exactlyOneLink ((LinkKeyCert _):_)    (Just _) = error "Too many link certs."
exactlyOneLink ((LinkKeyCert c):rest) Nothing  = exactlyOneLink rest (Just c)
exactlyOneLink (_:rest)               acc      = exactlyOneLink rest acc

exactlyOneId :: [TorCert] -> Maybe SignedCertificate -> SignedCertificate
exactlyOneId []                         Nothing  = error "Not enough id certs."
exactlyOneId []                         (Just x) = x
exactlyOneId ((RSA1024Identity _):_)    (Just _) = error "Too many id certs."
exactlyOneId ((RSA1024Identity c):rest) Nothing  = exactlyOneId rest (Just c)
exactlyOneId (_:rest)                   acc      = exactlyOneId rest acc

exactlyOneAuth :: [TorCert] -> Maybe SignedCertificate -> SignedCertificate
exactlyOneAuth []                     Nothing  = error "Not enough auth certs."
exactlyOneAuth []                     (Just x) = x
exactlyOneAuth ((RSA1024Auth _):_)    (Just _) = error "Too many auth certs."
exactlyOneAuth ((RSA1024Auth c):rest) Nothing  = exactlyOneAuth rest (Just c)
exactlyOneAuth (_:rest)               acc      = exactlyOneAuth rest acc

is1024BitRSAKey :: SignedCertificate -> Bool
is1024BitRSAKey cert =
  case certPubKey (signedObject (getSigned cert)) of
    PubKeyRSA pk -> public_size pk == 128
    _            -> False

certExpired :: Certificate -> DateTime -> Bool
certExpired cert t = (aft > t) || (t > unt)
 where (aft, unt) = certValidity cert

fromElapsed :: Integral t => Elapsed -> t
fromElapsed (Elapsed secs) = fromIntegral secs
