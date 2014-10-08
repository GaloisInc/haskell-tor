module Tor.Circuit(
         createCircuit
       , extendCircuit
       , destroyCircuit
       --
       , TorConnection(..)
       , resolveName
       , connectToHost
       , connectToHost'
       )
 where

import Codec.Crypto.RSA.Pure
import Control.Applicative
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Exception
import Control.Monad
import Crypto.Cipher.AES128
import Data.Binary.Get
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Digest.Pure.SHA1
import Data.Int
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Word
import TLS.Certificate
import TLS.DiffieHellman
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.HybridCrypto
import Tor.Link
import Tor.RouterDesc
import Tor.State

-- -----------------------------------------------------------------------------

data TorCircuit = TorCircuit {
       circForwardLink        :: TorLink
     , circCircuitId          :: Word32
     , circNextStreamId       :: MVar Word16
     , circExtendWaiter       :: MVar (Either DestroyReason ByteString)
     , circResolveWaiters     :: MVar (Map Word16 (MVar [(TorAddress, Word32)]))
     , circConnectionWaiters  :: MVar (Map Word16 (MVar (Either RelayEndReason TorConnection)))
     , circDataBuffers        :: MVar (Map Word16 (TVar ByteString))
     , circForwardCryptoData  :: MVar [(EncryptionState, SHA1State)]
     , circBackwardCryptoData :: MVar [(EncryptionState, SHA1State)]
     }

-- Send a cell downstream in the circuit, in the cirection of the CREATE
-- request, away from the originator of the circuit. If there is no downstream
-- (i.e., we're the exit node), then this triggers the destruction of the
-- circuit.
-- circSendDownstream :: TorCircuit -> TorCell -> IO ()
-- circSendDownstream = error "circSendDownstream"

-- Send a cell upstream in the circuit, towards the originator of the circuit.
-- If there is no upstream circuit (i.e., we're the origination point), then
-- this triggers the destruction of the circuit.
circSendUpstream :: TorCircuit -> TorCell -> IO ()
circSendUpstream _ _ =
  do putStrLn "WARNING: circSendUpstream"
     return ()

-- -----------------------------------------------------------------------------

createCircuit :: TorState ls s -> RouterDesc -> IO (Either String TorCircuit)
createCircuit torst firstRouter =
  handle (\ e -> return (Left (show (e :: SomeException)))) $
    do link <- failLeft <$> initializeClientTorLink torst firstRouter
       waitMV <- newEmptyMVar
       let initHand = createHandler link waitMV
       circId <- atomically $ withRNGSTM torst (newRandomCircuit link initHand)
       x <- withRNG torst generateLocal'
       let gx = computePublicValue oakley2 x
           Right gxBS = i2osp gx 128
       let nodePub = routerOnionKey firstRouter
       egx <- withRNG torst (hybridEncrypt True nodePub gxBS)
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
              let circ = TorCircuit {
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
extendCircuit :: TorState ls s -> TorCircuit -> RouterDesc ->
                 IO (Either String ())
extendCircuit torst circ nextRouter =
  do x <- withRNG torst generateLocal'
     let gx = computePublicValue oakley2 x
         Right gxBS = i2osp gx 128
     egx <- withRNG torst (hybridEncrypt True (routerOnionKey nextRouter) gxBS)
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

-- Destroy the circuit, sending the given reason upstream.
destroyCircuit :: TorCircuit -> DestroyReason -> IO ()
destroyCircuit circ reason =
  do _ <- tryPutMVar (circExtendWaiter circ) (Left reason)
     let circId = circCircuitId circ
         link   = circForwardLink circ
     writeCell link (Destroy circId reason)
     endCircuit link circId

-- -----------------------------------------------------------------------------

data TorConnection = TorConnection {
       torWrite :: ByteString -> IO ()
     , torRead  :: Int64 -> IO ByteString
     , torClose :: IO ()
     }

-- |Resolve the given name anonymously on the given circuit. In some cases,
-- you may receive error values amongst the responses. The Word32 provided with
-- each response is a TTL for that response.
resolveName :: TorCircuit -> String -> IO [(TorAddress, Word32)]
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
connectToHost :: TorCircuit -> TorAddress -> Word16 -> IO TorConnection
connectToHost tc a p = connectToHost' tc a p True True False

-- |Connect to the given address and port through the given circuit. The result
-- is a connection that can be used to read, write, and close the connection.
-- The booleans determine if an IPv4 connection is OK, an IPv6 connection is OK,
-- and whether IPv6 is preferred, respectively.
connectToHost' :: TorCircuit ->
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

writeCellOnCircuit :: TorCircuit -> RelayCell -> IO ()
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

getNextStreamId :: TorCircuit -> IO Word16
getNextStreamId circ = modifyMVar (circNextStreamId circ) $ \ x ->
  return (x + 1, x)

-- -----------------------------------------------------------------------------

-- This handler is called when we receive data from an earlier link in the
-- circuit. Thus, traffic we receive is moving forward through the network.
-- forwardRelayHandler :: TorState ls s -> TorCircuit -> TorCell -> IO ()
-- forwardRelayHandler torst circ cell = error "forwardRelayHandler"

-- This handler is called when we receive data from the next link in the
-- circuit. Thus, traffic we receive is moving backwards through the network.
backwardRelayHandler :: TorState ls s -> TorCircuit ->
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
         Just tv -> atomically $ do orig <- readTVar tv
                                    writeTVar tv (orig `BS.append` block)
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
  decryptUntilClean :: ByteString -> [(EncryptionState, SHA1State)] ->
                       ([(EncryptionState, SHA1State)], Maybe RelayCell)
  decryptUntilClean _    []                    = ([], Nothing)
  decryptUntilClean bstr ((encstate, h1):rest) =
    let (bstr', encstate') = decryptData encstate bstr
    in case runGetOrFail (parseRelayCell h1) bstr' of
         Left _ ->
           let (rest', res) = decryptUntilClean bstr' rest
           in ((encstate', h1) : rest', res)
         Right (_, _, (x, h1')) ->
           (((encstate', h1') : rest), Just x)

-- -----------------------------------------------------------------------------

buildConnection :: TorCircuit -> Word16 -> IO TorConnection
buildConnection circ strmId =
  do readTV <- newTVarIO BS.empty
     modifyMVar_ (circDataBuffers circ) $ \ dbmap ->
       return (Map.insert strmId readTV dbmap)
     return TorConnection{
              torRead  = readBytes readTV
            , torWrite = writeBytes circ strmId
            , torClose = closeConnection circ strmId
            }

readBytes :: TVar ByteString -> Int64 -> IO ByteString
readBytes _      0   =
  return BS.empty
readBytes bstrTV amt =
  do start <- atomically $ do buffer <- readTVar bstrTV
                              when (BS.null buffer) retry
                              let (res, rest) = BS.splitAt amt buffer
                              writeTVar bstrTV rest
                              return res
     (start `BS.append`) <$> readBytes bstrTV (amt - BS.length start)

writeBytes :: TorCircuit -> Word16 -> ByteString -> IO ()
writeBytes circ strmId bstr
  | BS.null bstr = return ()
  | otherwise    =
      do let (cur, rest) = BS.splitAt 503 bstr
         writeCellOnCircuit circ (RelayData strmId cur)
         writeBytes circ strmId rest

closeConnection :: TorCircuit -> Word16 -> IO ()
closeConnection c strmId = writeCellOnCircuit c (RelayEnd strmId ReasonDone)

-- -----------------------------------------------------------------------------

newtype EncryptionState = ES ByteString

initEncryptionState :: AESKey128 -> EncryptionState
initEncryptionState k = ES (xorStream k)

encryptData :: EncryptionState -> ByteString -> (ByteString, EncryptionState)
encryptData (ES state) bstr =
  let (ebstr, state') = BS.splitAt (BS.length bstr) state
  in (xorBS ebstr bstr, ES state')

decryptData :: EncryptionState -> ByteString -> (ByteString, EncryptionState)
decryptData = encryptData

xorStream :: AESKey128 -> ByteString
xorStream k = BS.fromChunks (go (0 :: Integer))
 where
  go x =
    case i2osp x 16 of
      Left e     -> error ("Error building xorStream: " ++ show e)
      Right bstr ->
        let firstBit = encryptBlock k (BS.toStrict bstr)
        in firstBit : go (x + 1)

xorBS :: ByteString -> ByteString -> ByteString
xorBS a b = BS.pack (BS.zipWith xor a b)

-- -----------------------------------------------------------------------------

generateLocal' :: TorRNG -> (Integer, TorRNG)
generateLocal' g =
  case generateLocal oakley2 g of
    Left err      -> error ("generateLocal': " ++ show err)
    Right (x, g') -> (x, g')

completeTAPHandshake :: Integer -> Either DestroyReason ByteString ->
                        Either String ((EncryptionState, SHA1State),
                                       (EncryptionState, SHA1State))
completeTAPHandshake _ (Left drsn) = Left (show drsn)
completeTAPHandshake x (Right rbstr)
  | kh == kh' = Right ((encsf, fhash), (encsb, bhash))
  | otherwise = Left "Key agreement failure."
 where
  (gyBS, kh)   = BS.splitAt 128 rbstr
  gy           = os2ip gyBS
  k0           = computeSharedSecret oakley2 gy x
  (kh', rest1) = BS.splitAt 20 (kdfTor k0)
  (df,  rest2) = BS.splitAt 20  rest1
  (db,  rest3) = BS.splitAt 20  rest2
  (kf,  rest4) = BS.splitAt 16  rest3
  (kb,  _)     = BS.splitAt 16  rest4
  Just keyf    = buildKey (BS.toStrict kf)
  Just keyb    = buildKey (BS.toStrict kb)
  encsf        = initEncryptionState keyf
  encsb        = initEncryptionState keyb
  fhash        = advanceSHA1State initialSHA1State df
  bhash        = advanceSHA1State initialSHA1State db

kdfTor :: ByteString -> ByteString
kdfTor k0 = BS.concat (map kdfTorChunk [0..255])
  where kdfTorChunk x = sha1 (BS.snoc k0 x)


