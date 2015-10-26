module Tor.Circuit(
         TorEntrance
       , createCircuit
       , extendCircuit
       , destroyCircuit
       --
       , buildRelay
       , buildRelayFast
       --
       , TorConnection(..)
       , resolveName
       , connectToHost
       , connectToHost'
       )
 where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Exception
import Control.Monad
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash hiding (hash)
import Crypto.Hash.Easy
import Crypto.Number.Serialize
import Crypto.PubKey.DH
import Crypto.PubKey.RSA.KeyHash
import Crypto.Random
import Data.Binary.Get
import Data.Bits
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Tuple
import Data.Word
import Data.X509
import Network.TLS(HasBackend)
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.HybridCrypto
import Tor.Link
import Tor.Link.DH
import Tor.RNG
import Tor.RouterDesc

-- -----------------------------------------------------------------------------

type ConnectionResp = Either RelayEndReason TorConnection

data TorEntrance = TorEntrance {
      circForwardLink        :: TorLink
    , circCircuitId          :: Word32
    , circNextStreamId       :: MVar Word16
    , circExtendWaiter       :: MVar (Either DestroyReason ByteString)
    , circResolveWaiters     :: MVar (Map Word16 (MVar [(TorAddress, Word32)]))
    , circConnectionWaiters  :: MVar (Map Word16 (MVar ConnectionResp))
    , circDataBuffers        :: MVar (Map Word16 (MVar ByteString))
    , circForwardCryptoData  :: MVar [(EncryptionState, Context SHA1)]
    , circBackwardCryptoData :: MVar [(EncryptionState, Context SHA1)]
    }

data ForwardState = ForwardLink {
                      flLink                :: TorLink
                    , flCircuitId           :: Word32
                    }
                  | ForwardExtending {
                    }
                  | ForwardExit {
                    }
                  | ForwardDeadEnd


data TorRelay = TorRelay {
      relayBackwardLink        :: TorLink
    , relayBackwardCircId      :: Word32
    , relayForwardCryptoData   :: MVar (EncryptionState, Context SHA1)
    , _relayBackwardCryptoData :: MVar (EncryptionState, Context SHA1)
    , relayForwardStates       :: MVar ForwardState
    }

-- Send a cell downstream in the circuit, in the cirection of the CREATE
-- request, away from the originator of the circuit. If there is no downstream
-- (i.e., we're the exit node), then this triggers the destruction of the
-- circuit.
-- circSendDownstream :: TorEntrance -> TorCell -> IO ()
-- circSendDownstream = error "circSendDownstream"

-- Send a cell upstream in the circuit, towards the originator of the circuit.
-- If there is no upstream circuit (i.e., we're the origination point), then
-- this triggers the destruction of the circuit.
circSendUpstream :: TorEntrance -> TorCell -> IO ()
circSendUpstream _ _ =
  do putStrLn "WARNING: circSendUpstream"
     return ()

-- -----------------------------------------------------------------------------

createCircuit :: MVar TorRNG -> TorLink -> Word32 -> IO TorEntrance
createCircuit rngMV link circId =
  do x <- modifyMVar rngMV generateLocal'
     let PublicNumber gx = calculatePublic oakley2 x
         gxBS = i2ospOf_ 128 gx
     let nodePub = routerOnionKey firstRouter
     egx <- hybridEncrypt True nodePub gxBS
     writeCell link (Create circId egx)
     initres <- takeMVar waitMV
     case completeTAPHandshake x initres of
       Left err -> return (Left err)
       Right (fencstate, bencstate) ->
         do fencMV <- newMVar [fencstate]
            bencMV <- newMVar [bencstate]
            strmMV <- newMVar 1
            ewMV   <- newEmptyMVar
            rsvMV  <- newMVar Map.empty
            conMV  <- newMVar Map.empty
            dbfMV  <- newMVar Map.empty
            let circ = TorEntrance {
                         circForwardLink        = link
                       , circCircuitId          = circId
                       , circNextStreamId       = strmMV
                       , circExtendWaiter       = ewMV
                       , circResolveWaiters     = rsvMV
                       , circConnectionWaiters  = conMV
                       , circDataBuffers        = dbfMV
                       , circForwardCryptoData  = fencMV
                       , circBackwardCryptoData = bencMV
                       }
                handler' = backwardRelayHandler torst circ
            modifyCircuitHandler link circId handler'
            return (Right circ)
 where
  failLeft (Left str) = error str
  failLeft (Right x)  = x
  --
  createHandler :: TorLink -> MVar (Either DestroyReason ByteString) ->
                   TorCell ->
                   IO ()
  createHandler link waitMV cell =
    case cell of
      Created circId bstr
        | BS.length bstr == (128 + 20) -> -- DH_LEN + HASH_LEN
            putMVar waitMV (Right bstr)
        | otherwise ->
            do logMsg torst ("Got CREATED message with bad length.")
               endCircuit link circId
      Destroy _ reason ->
        putMVar waitMV (Left reason)
      _ ->
        logMsg torst ("Ignoring spurious message while waiting " ++
                      "for CREATED: " ++ show cell)

-- |Given a circuit, extend the end to the given router.
extendCircuit :: TorState ls s -> TorEntrance -> RouterDesc ->
                 IO (Either String ())
extendCircuit torst circ nextRouter =
  do x <- withRNG torst generateLocal'
     let PublicNumber gx = calculatePublic oakley2 x
         gxBS = i2ospOf_ 128 gx
     egx <- hybridEncrypt True (routerOnionKey nextRouter) gxBS
     writeCellOnCircuit circ (extendCell egx)
     res <- takeMVar (circExtendWaiter circ)
     case completeTAPHandshake x res of
       Left err -> return (Left err)
       Right (fencstate, bencstate) ->
         do modifyMVar_ (circForwardCryptoData circ) $ \ rest ->
              return (rest ++ [fencstate])
            modifyMVar_ (circBackwardCryptoData circ) $ \ rest ->
              return (rest ++ [bencstate])
            return (Right ())
 where
  extendCell skin = RelayExtend {
      relayStreamId      = 0
    , relayExtendAddress = IP4 (routerIPv4Address nextRouter)
    , relayExtendPort    = routerORPort nextRouter
    , relayExtendSkin    = skin
    , relayExtendIdent   = keyHash' sha1 (routerSigningKey nextRouter)
    }

-- -----------------------------------------------------------------------------

buildRelay :: TorState ls s -> TorLink -> Word32 -> ByteString -> IO ()
buildRelay torst link circId egx = catch buildInCircuit' internalError
 where
  buildInCircuit' =
    do (_, PrivKeyRSA nodePriv) <- getOnionCredentials torst
       gxBS                     <- hybridDecrypt nodePriv egx
       y                        <- withRNG torst generateLocal'
       let gx              = PublicNumber (os2ip gxBS)
           PublicNumber gy = calculatePublic oakley2 y
           gyBS            = i2ospOf_ 128 gy
           (kh, f, b)      = computeTAPValues y gx
           resp            = gyBS `BS.append` kh
       fMV  <- newMVar f
       bMV  <- newMVar b
       flMV <- newMVar ForwardDeadEnd
       let relay = TorRelay link circId fMV bMV flMV
       modifyCircuitHandler link circId (forwardRelayHandler torst relay)
       writeCell link (Created circId resp)
  --
  internalError :: SomeException -> IO ()
  internalError e =
    do logMsg torst ("Internal error building circuit: " ++ show e)
       writeCell link (Destroy circId InternalError)

buildRelayFast :: TorState ls s -> TorLink -> Word32 -> ByteString -> IO ()
buildRelayFast = error "FIXME: buildRelayFast"

-- -----------------------------------------------------------------------------

-- Destroy the circuit, sending the given reason upstream.
destroyCircuit :: TorEntrance -> DestroyReason -> IO ()
destroyCircuit circ reason =
  do _ <- tryPutMVar (circExtendWaiter circ) (Left reason)
     let circId = circCircuitId circ
         link   = circForwardLink circ
     writeCell link (Destroy circId reason)
     endCircuit link circId

-- -----------------------------------------------------------------------------

data TorConnection = TorConnection {
       torWrite :: ByteString -> IO ()
     , torRead  :: Int -> IO ByteString
     , torClose :: IO ()
     }

-- |Resolve the given name anonymously on the given circuit. In some cases,
-- you may receive error values amongst the responses. The Word32 provided with
-- each response is a TTL for that response.
resolveName :: TorEntrance -> String -> IO [(TorAddress, Word32)]
resolveName circ str =
  do strmId <- getNextStreamId circ
     resMV  <- newEmptyMVar
     modifyMVar_ (circResolveWaiters circ) $ \ m ->
       return (Map.insert strmId resMV m)
     writeCellOnCircuit circ (RelayResolve strmId str)
     takeMVar resMV

-- |Connect to the given address and port through the given circuit. The result
-- is a connection that can be used to read, write, and close the connection.
-- (This is equivalent to calling connectToHost' with True, True, and False for
-- the extra arguments.
connectToHost :: TorEntrance -> TorAddress -> Word16 -> IO TorConnection
connectToHost tc a p = connectToHost' tc a p True True False

-- |Connect to the given address and port through the given circuit. The result
-- is a connection that can be used to read, write, and close the connection.
-- The booleans determine if an IPv4 connection is OK, an IPv6 connection is OK,
-- and whether IPv6 is preferred, respectively.
connectToHost' :: TorEntrance ->
                  TorAddress -> Word16 ->
                  Bool -> Bool -> Bool ->
                  IO TorConnection
connectToHost' circ addr port ip4ok ip6ok ip6pref =
  do strmId <- getNextStreamId circ
     resMV  <- newEmptyMVar
     modifyMVar_ (circConnectionWaiters circ) $ \ m ->
       return (Map.insert strmId resMV m)
     writeCellOnCircuit circ (RelayBegin strmId addr port ip4ok ip6ok ip6pref)
     throwLeft =<< takeMVar resMV
 where
  throwLeft (Left a)  = throwIO a
  throwLeft (Right x) = return x

-- -----------------------------------------------------------------------------

writeCellOnCircuit :: TorEntrance -> RelayCell -> IO ()
writeCellOnCircuit circ relay =
  do keysnhashes <- takeMVar (circForwardCryptoData circ)
     let (cell, keysnhashes') = synthesizeRelay keysnhashes
         circId               = circCircuitId circ
     writeCell (circForwardLink circ) (pickBuilder relay circId cell)
     putMVar (circForwardCryptoData circ) keysnhashes'
 where
  synthesizeRelay [] = error "synthesizeRelay reached empty list?!"
  synthesizeRelay [(estate, hash)] =
    let (bstr, hash')      = renderRelayCell hash relay
        (encbstr, estate') = encryptData estate bstr
    in (encbstr, [(estate', hash')])
  synthesizeRelay ((estate, hash) : rest) =
    let (bstr, rest')      = synthesizeRelay rest
        (encbstr, estate') = encryptData estate bstr
    in (encbstr, (estate', hash) : rest')
  --
  pickBuilder RelayExtend{}  = RelayEarly
  pickBuilder RelayExtend2{} = RelayEarly
  pickBuilder _              = RelayEarly

getNextStreamId :: TorEntrance -> IO Word16
getNextStreamId circ = modifyMVar (circNextStreamId circ) $ \ x ->
  return (x + 1, x)

-- -----------------------------------------------------------------------------

-- This handler is called when we receive data from an earlier link in the
-- circuit. Thus, traffic we receive is moving forward through the network.
forwardRelayHandler :: TorState ls s -> TorRelay -> TorCell -> IO ()
forwardRelayHandler torst circ cell =
  case cell of
    Relay _ body      -> forwardRelay Relay      body
    RelayEarly _ body -> forwardRelay RelayEarly body
    Destroy _ reason  -> logMsg torst ("Relay destroyed: " ++ show reason)
    _                 -> logMsg torst ("Spurious message across relay.")
 where
  forwardRelay builder body =
    do (encstate, hashstate) <- takeMVar (relayForwardCryptoData circ)
       let (body', encstate') = decryptData encstate body
       case runGetOrFail (parseRelayCell hashstate) (BSL.fromStrict body') of
         Left _ ->
           do putMVar (relayForwardCryptoData circ) (encstate', hashstate)
              forward builder body'
         Right (_, _, (x, hashstate')) ->
           do putMVar (relayForwardCryptoData circ) (encstate', hashstate')
              process x
  --
  forward builder bstr =
    do fstate <- takeMVar (relayForwardStates circ)
       case fstate of
         ForwardLink{} ->
            do writeCell (flLink fstate) (builder (flCircuitId fstate) bstr)
               putMVar (relayForwardStates circ) fstate
         ForwardExtending{} ->
            do putMVar (relayForwardStates circ) ForwardDeadEnd
               let dst = Destroy (relayBackwardCircId circ) TorProtocolViolation
               writeCell (relayBackwardLink circ) dst
               endCircuit (relayBackwardLink circ) (relayBackwardCircId circ)
         ForwardExit{} ->
            do putMVar (relayForwardStates circ) ForwardDeadEnd
               let dst = Destroy (relayBackwardCircId circ) TorProtocolViolation
               writeCell (relayBackwardLink circ) dst
               endCircuit (relayBackwardLink circ) (relayBackwardCircId circ)
         ForwardDeadEnd ->
            return ()
  --
  process RelayBegin{}    = putStrLn "RELAY_BEGIN"
  process RelayData{}     = putStrLn "RELAY_DATA"
  process RelayEnd{}      = putStrLn "RELAY_END"
  process RelayExtend{}   = putStrLn "RELAY_DATA"
  process RelayTruncate{} = putStrLn "RELAY_TRUNCATE"
  process RelayDrop{}     = putStrLn "RELAY_DROP"
  process RelayResolve{}  = putStrLn "RELAY_RESOLVE"
  process RelayExtend2{}  = putStrLn "RELAY_EXTEND2"
  process _               = return ()

-- This handler is called when we receive data from the next link in the
-- circuit. Thus, traffic we receive is moving backwards through the network.
backwardRelayHandler :: TorState ls s -> TorEntrance ->
                        TorCell -> IO ()
backwardRelayHandler torst circ cell =
  case cell of
    Relay cnum body ->
      do keysnhashes <- takeMVar (circBackwardCryptoData circ)
         let (keysnhashes', res) = decryptUntilClean body keysnhashes
         putMVar (circBackwardCryptoData circ) keysnhashes'
         case res of
           Nothing -> circSendUpstream circ (Relay cnum body)
           Just x ->
             case x of
               RelayData{}      -> addDataBlock x (relayData x)
               RelayEnd{}       -> do destroyConnection x    (relayEndReason x)
                                      destroyCircuit    circ CircuitDestroyed
               RelayConnected{} -> finalizeConnect x
               RelaySendMe{}    -> logMsg torst ("Received (B) RELAY_SENDME")
               RelayExtended{}  -> continueExtend (relayExtendedData x)
               RelayTruncated{} -> answerResolve x []
               RelayDrop{}      -> return ()
               RelayResolved{}  -> answerResolve x (relayResolvedAddrs x)
               RelayExtended2{} -> return () -- FIXME
               _                -> return ()
    RelayEarly cnum body ->
      -- Treat RelayEarly as Relay. This could be a problem. FIXME?
      backwardRelayHandler torst circ (Relay cnum body)
    Destroy _ reason ->
      do logMsg torst ("Circuit destroyed: " ++ show reason)
         destroyCircuit circ reason
    _ ->
      logMsg torst ("Spurious message along relay.")
 where
  addDataBlock x block =
    do mmv <- getDeleteFromMap (circDataBuffers circ) (relayStreamId x)
       case mmv of
         Nothing -> return ()
         Just mv -> do orig <- takeMVar mv
                       putMVar mv (orig `BS.append` block)
  getDeleteFromMap mapMV key =
    modifyMVar mapMV $ \ mvmap ->
      return (Map.delete key mvmap, Map.lookup key mvmap)
  answerResolve x result =
    do mmv <- getDeleteFromMap (circResolveWaiters circ) (relayStreamId x)
       case mmv of
         Nothing -> return ()
         Just mv -> putMVar mv result
  --
  continueExtend extdata =
    do ok <- tryPutMVar (circExtendWaiter circ) (Right extdata)
       unless ok $ destroyCircuit circ InternalError
  --
  destroyConnection x reason =
   do mmv <- getDeleteFromMap (circConnectionWaiters circ) (relayStreamId x)
      case mmv of
        Nothing -> return ()
        Just mv -> putMVar mv (Left reason)
      _ <- getDeleteFromMap (circDataBuffers circ) (relayStreamId x)
      return ()
  --
  finalizeConnect x =
   do mmv <- getDeleteFromMap (circConnectionWaiters circ) (relayStreamId x)
      case mmv of
        Nothing -> return ()
        Just mv ->
          do res <- buildConnection circ (relayStreamId x)
             putMVar mv (Right res)
  --
  decryptUntilClean :: ByteString -> [(EncryptionState, Context SHA1)] ->
                       ([(EncryptionState, Context SHA1)], Maybe RelayCell)
  decryptUntilClean _    []                    = ([], Nothing)
  decryptUntilClean bstr ((encstate, h1):rest) =
    let (bstr', encstate') = decryptData encstate bstr
    in case runGetOrFail (parseRelayCell h1) (BSL.fromStrict bstr') of
         Left _ ->
           let (rest', res) = decryptUntilClean bstr' rest
           in ((encstate', h1) : rest', res)
         Right (_, _, (x, h1')) ->
           (((encstate', h1') : rest), Just x)

-- -----------------------------------------------------------------------------

buildConnection :: TorEntrance -> Word16 -> IO TorConnection
buildConnection circ strmId =
  do readMV <- newMVar BS.empty
     modifyMVar_ (circDataBuffers circ) $ \ dbmap ->
       return (Map.insert strmId readMV dbmap)
     return TorConnection{
              torRead  = readBytes readMV
            , torWrite = writeBytes circ strmId
            , torClose = closeConnection circ strmId
            }

readBytes :: MVar ByteString -> Int -> IO ByteString
readBytes bstrMV total = BS.concat `fmap` loop total
 where
  loop 0   = return []
  loop amt = do buffer <- takeMVar bstrMV
                let (res, rest) = BS.splitAt amt buffer
                putMVar bstrMV rest
                (res :) `fmap` loop (amt - BS.length res)

writeBytes :: TorEntrance -> Word16 -> ByteString -> IO ()
writeBytes circ strmId bstr
  | BS.null bstr = return ()
  | otherwise    =
      do let (cur, rest) = BS.splitAt 503 bstr
         writeCellOnCircuit circ (RelayData strmId cur)
         writeBytes circ strmId rest

closeConnection :: TorEntrance -> Word16 -> IO ()
closeConnection c strmId = writeCellOnCircuit c (RelayEnd strmId ReasonDone)

-- -----------------------------------------------------------------------------

newtype EncryptionState = ES BSL.ByteString

initEncryptionState :: AES128 -> EncryptionState
initEncryptionState k = ES (xorStream k)

encryptData :: EncryptionState -> ByteString -> (ByteString, EncryptionState)
encryptData (ES state) bstr =
  let (ebstr, state') = BSL.splitAt (fromIntegral (BS.length bstr)) state
  in (xorBS (BSL.toStrict ebstr) bstr, ES state')

decryptData :: EncryptionState -> ByteString -> (ByteString, EncryptionState)
decryptData = encryptData

xorStream :: AES128 -> BSL.ByteString
xorStream k = BSL.fromChunks (go 0)
 where
  go :: Integer -> [ByteString]
  go x = ecbEncrypt k (i2ospOf_ 16 x) : go (plus1' x)
  --
  plus1' x = (x + 1) `mod` (2 ^ (128 :: Integer))

xorBS :: ByteString -> ByteString -> ByteString
xorBS a b = BS.pack (BS.zipWith xor a b)

-- -----------------------------------------------------------------------------

generateLocal' :: TorRNG -> (TorRNG, PrivateNumber)
generateLocal' g = swap (withDRG g (generatePrivate oakley2))

completeTAPHandshake :: PrivateNumber ->
                        Either DestroyReason ByteString ->
                        Either String ((EncryptionState, Context SHA1),
                                       (EncryptionState, Context SHA1))
completeTAPHandshake _ (Left drsn)   = Left (show drsn)
completeTAPHandshake x (Right rbstr)
  | kh == kh' = Right (f, b)
  | otherwise = Left "Key agreement failure."
 where
  (gyBS, kh)   = BS.splitAt 128 rbstr
  gy           = PublicNumber (os2ip gyBS)
  (kh', f, b)  = computeTAPValues x gy

computeTAPValues :: PrivateNumber -> PublicNumber ->
                    (ByteString, (EncryptionState, Context SHA1),
                                 (EncryptionState, Context SHA1))
computeTAPValues b ga = (kh, (encsf, fhash), (encsb, bhash))
 where
  SharedKey k0 = getShared oakley2 b ga
  (kh, rest1)  = BS.splitAt 20 (kdfTor (i2ospOf_ 128 k0))
  (df,  rest2) = BS.splitAt 20  rest1
  (db,  rest3) = BS.splitAt 20  rest2
  (kf,  rest4) = BS.splitAt 16  rest3
  (kb,  _)     = BS.splitAt 16  rest4
  keyf         = throwCryptoError (cipherInit kf)
  keyb         = throwCryptoError (cipherInit kb)
  encsf        = initEncryptionState keyf
  encsb        = initEncryptionState keyb
  fhash        = hashUpdate hashInit df
  bhash        = hashUpdate hashInit db

kdfTor :: ByteString -> ByteString
kdfTor k0 = BS.concat (map kdfTorChunk [0..255])
  where kdfTorChunk x = sha1 (BS.snoc k0 x)
