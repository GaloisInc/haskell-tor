{-# LANGUAGE RecordWildCards #-}
module Tor.Circuit(
       -- * High-level type for Tor circuits, and operations upon them.
         TorCircuit
       , createCircuit
       , acceptCircuit
       , destroyCircuit
       , extendCircuit
       -- * Name resolution support.
       , resolveName
       -- * Tor sockets.
       , TorSocket(..)
       , connectToHost
       , connectToHost'
       , torRead
       , torWrite
       , torClose
       -- * Miscellaneous routines, mostly exported for testing.
       , startTAPHandshake
       , advanceTAPHandshake
       , completeTAPHandshake
       , startNTorHandshake
       , advanceNTorHandshake
       , completeNTorHandshake
       , generate25519
       )
 where

import Control.Concurrent
import Control.Exception
import Control.Monad(void, when, unless, forever, join)
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash hiding (hash)
import Crypto.Hash.Easy
import Crypto.MAC.HMAC(hmac,HMAC)
import Crypto.Number.Serialize
import Crypto.PubKey.Curve25519 as Curve
import Crypto.PubKey.DH
import Crypto.PubKey.RSA.KeyHash
import Crypto.PubKey.RSA.Types
import Crypto.Random
import Data.Binary.Get
import Data.Bits
import Data.ByteArray(ByteArrayAccess,ByteArray,convert)
import Data.ByteString(ByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import Data.Either
#if !MIN_VERSION_base(4,8,0)
import Data.Foldable hiding (all)
#endif
import Data.IntSet(IntSet)
import qualified Data.IntSet as IntSet
import Data.Maybe
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Tuple
import Data.Word
import Hexdump
#if !MIN_VERSION_base(4,8,0)
import Prelude hiding (mapM_)
#endif
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.HybridCrypto
import Tor.Link
import Tor.Link.DH
import Tor.RNG
import Tor.RouterDesc

-- -----------------------------------------------------------------------------

data TorCircuit =
       OriginatedTorCircuit {
         circLink            :: TorLink
       , circLog             :: String -> IO ()
       , circId              :: Word32
       , circRNG             :: MVar TorRNG
       , circState           :: MVar (Either DestroyReason [ThreadId])
       , circTakenStreamIds  :: MVar IntSet
       , circExtendWaiter    :: MVar RelayCell
       , circResolveWaiters  :: MVar (Map Word16 (MVar [(TorAddress, Word32)]))
       , circSockets         :: MVar (Map Word16 TorSocket)
       , circConnWaiters     :: MVar (Map Word16 (MVar (Either String TorSocket)))
       , circForeCryptoData  :: MVar [(EncryptionState, Context SHA1)]
       , circBackCryptoData  :: MVar [(EncryptionState, Context SHA1)]
       }
     | TransverseTorCircuit {
         circLink            :: TorLink
       , circLog             :: String -> IO ()
       , circId              :: Word32
       , circRNG             :: MVar TorRNG
       , circForeCryptoData  :: MVar [(EncryptionState, Context SHA1)]
       , circBackCryptoData  :: MVar [(EncryptionState, Context SHA1)]
       }

createCircuit :: MVar TorRNG -> (String -> IO ()) ->
                 TorLink -> RouterDesc -> Word32 ->
                 IO TorCircuit
createCircuit circRNG circLog circLink router1 circId =
  case routerNTorOnionKey router1 of
    Nothing ->
      do (x,cbstr) <- modifyMVar circRNG (return . startTAPHandshake router1)
         linkWrite circLink (Create circId cbstr)
         createResp <- linkRead circLink circId
         case createResp of
           Created cid bstr                       -- DH_LEN + HASH_LEN
             | (circId == cid) && (S.length bstr == (128    + 20)) ->
                case completeTAPHandshake x bstr of
                  Left err ->
                    failLog ("CREATE handshake failed: " ++ err)
                  Right (fencstate, bencstate) ->
                    do circForeCryptoData <- newMVar [fencstate]
                       circBackCryptoData <- newMVar [bencstate]
                       circState          <- newEmptyMVar
                       circTakenStreamIds <- newMVar IntSet.empty
                       circExtendWaiter   <- newEmptyMVar
                       circSockets        <- newMVar Map.empty
                       circResolveWaiters <- newMVar Map.empty
                       circConnWaiters    <- newMVar Map.empty
                       let circ = OriginatedTorCircuit { .. }
                       handler <- forkIO (runBackward circ)
                       putMVar circState (Right [handler])
                       circLog ("Created circuit " ++ show circId)
                       return circ
             | otherwise ->
                 failLog ("Got CREATED message with bad length")
           Destroy _ reason ->
             failLog ("Target circuit entrance refused handshake: " ++ show reason)
           _ ->
             failLog ("Unacceptable response to CREATE message.")
    Just _ ->
      do res <- modifyMVar circRNG (return . startNTorHandshake router1)
         case res of
           Nothing ->
             failLog ("Couldn't generate initial NTor handshake message.")
           Just (pair, cbody) ->
             do linkWrite circLink (Create2 circId NTor cbody)
                createResp <- linkRead circLink circId
                case createResp of
                  Created2 cid bstr                     -- G_LENGTH + H_LENGTH
                    | (circId == cid) && (S.length bstr == (32      + 32)) ->
                       case completeNTorHandshake router1 pair bstr of
                         Left err ->
                           failLog ("CREATE2 handshake failed: " ++ err)
                         Right (fencstate, bencstate) ->
                           do circForeCryptoData <- newMVar [fencstate]
                              circBackCryptoData <- newMVar [bencstate]
                              circState          <- newEmptyMVar
                              circTakenStreamIds <- newMVar IntSet.empty
                              circExtendWaiter   <- newEmptyMVar
                              circSockets        <- newMVar Map.empty
                              circResolveWaiters <- newMVar Map.empty
                              circConnWaiters    <- newMVar Map.empty
                              let circ = OriginatedTorCircuit { .. }
                              handler <- forkIO (runBackward circ)
                              putMVar circState (Right [handler])
                              circLog ("Created circuit (ntor) " ++ show circId)
                              return circ
                    | otherwise ->
                        failLog ("Got CREATED2 message with bad length")
                  Destroy _ reason ->
                    failLog ("Target entrance (ntor) refused handshake: "
                             ++ show reason)
                  _ ->
                    failLog ("Unacceptable response to CREATE2 message.")

 where
  failLog str = circLog str >> throwIO (userError str)
  runBackward circ =
    forever $ do next <- linkRead circLink circId
                 processBackwardInput circ next

acceptCircuit :: (String -> IO ()) -> PrivateKey ->
                 TorLink -> MVar TorRNG ->
                 IO TorCircuit
acceptCircuit circLog priv circLink circRNG =
  do msg <- linkRead circLink 0
     case msg of
       Create circId bstr ->
         do (created, fes, bes) <- modifyMVar circRNG
                                    (return . advanceTAPHandshake priv circId bstr)
            circForeCryptoData <- newMVar [fes]
            circBackCryptoData <- newMVar [bes]
            let circ            = TransverseTorCircuit { .. }
            linkWrite circLink created
            circLog ("Created transverse circuit " ++ show circId)
            return circ
       CreateFast _circId _bstr ->
         undefined
       Create2 _circId _hsType _bstr ->
         undefined
       _ ->
         undefined


-- |Destroy a circuit, and all the streams and computations running through it.
destroyCircuit :: TorCircuit -> DestroyReason -> IO ()
destroyCircuit circ rsn =
  do ts <- modifyMVar (circState circ) $ \ state ->
            case state of
              Left _ -> return (state, [])
              Right threads ->
                do mapM_ killSockets     =<< readMVar (circSockets circ)
                   mapM_ killConnWaiters =<< readMVar (circConnWaiters circ)
                   mapM_ killResWaiters  =<< readMVar (circResolveWaiters circ)
                   -- FIXME: Send a message out, kill the crypto after
                   _ <- takeMVar (circForeCryptoData circ)
                   _ <- takeMVar (circBackCryptoData circ)
                   circLog circ ("Destroy circuit " ++ show (circId circ))
                   return (Left rsn, threads)
     mapM_ killThread ts
 where
  killSockets sock =
    do modifyMVar_ (tsState sock) (const (return (Just ReasonDestroyed)))
       writeChan (tsInChan sock) (Left ReasonDestroyed)
  killConnWaiters mv =
    void $ tryPutMVar mv (Left ("Underlying circuit destroyed: " ++ show rsn))
  killResWaiters mv =
    void $ tryPutMVar mv []

extendCircuit :: TorCircuit -> RouterDesc -> IO ()
extendCircuit circ nextRouter =
  do state <- readMVar (circState circ)
     when (isLeft state) $
       throwIO (userError ("Attempted to extend a closed circuit."))
     (x, ebstr) <- modifyMVar (circRNG circ)
                     (return . startTAPHandshake nextRouter)
     writeCellOnCircuit circ (extendCell ebstr)
     res <- takeMVar (circExtendWaiter circ)
     case res of
       RelayExtended{} ->
         case completeTAPHandshake x (relayExtendedData res) of
           Left err ->
             throwIO (userError ("Failed extension handshake on circuit " ++
                                 show (circId circ) ++ ": " ++ err))
           Right (fencstate, bencstate) ->
             do modifyMVar_ (circForeCryptoData circ) $ \ rest ->
                  return (rest ++ [fencstate])
                modifyMVar_ (circBackCryptoData circ) $ \ rest ->
                  return (rest ++ [bencstate])
                return ()
       _ ->
         throwIO (userError ("Illegal response to EXTEND request on circuit" ++
                             (show (circId circ))))
 where
  extendCell skin = RelayExtend {
      relayStreamId      = 0
    , relayExtendAddress = IP4 (routerIPv4Address nextRouter)
    , relayExtendPort    = routerORPort nextRouter
    , relayExtendSkin    = skin
    , relayExtendIdent   = keyHash' sha1 (routerSigningKey nextRouter)
    }

-- ----------------------------------------------------------------------------

writeCellOnCircuit :: TorCircuit -> RelayCell -> IO ()
writeCellOnCircuit circ relay =
  do keysnhashes <- takeMVar (circForeCryptoData circ)
     let (cell, keysnhashes') = synthesizeRelay keysnhashes
     linkWrite (circLink circ) (pickBuilder relay (circId circ) cell)
     putMVar (circForeCryptoData circ) keysnhashes'
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

circSendUpstream :: TorCircuit -> TorCell -> IO ()
circSendUpstream = error "circSendUpstream"

-- ----------------------------------------------------------------------------

processBackwardInput :: TorCircuit -> TorCell -> IO ()
processBackwardInput circ cell =
  handle logException $
    case cell of
      Relay      circId body -> processBackwardRelay circ circId body
      RelayEarly circId body -> processBackwardRelay circ circId body
      Destroy    _      rsn  -> destroyCircuit circ rsn
      _                      ->
        circLog circ ("Spurious message along circuit.")
 where
  logException e =
    circLog circ ("Caught exception processing backwards input: "
                  ++ show (e :: SomeException))

processBackwardRelay :: TorCircuit -> Word32 -> ByteString -> IO ()
processBackwardRelay circ circId body =
  do clearBody <- modifyMVar (circBackCryptoData circ)
                    (return . decryptUntilClean body)
     case clearBody of
       Nothing -> circSendUpstream circ (Relay circId body)
       Just x  -> processLocalBackwardsRelay circ x
 where
  decryptUntilClean :: ByteString -> [(EncryptionState, Context SHA1)] ->
                       ([(EncryptionState, Context SHA1)], Maybe RelayCell)
  decryptUntilClean _    []                    = ([], Nothing)
  decryptUntilClean bstr ((encstate, h1):rest) =
    let (bstr', encstate') = decryptData encstate bstr
    in case runGetOrFail (parseRelayCell h1) (L.fromStrict bstr') of
         Left _ ->
           let (rest', res) = decryptUntilClean bstr' rest
           in ((encstate', h1) : rest', res)
         Right (_, _, (x, h1')) ->
           (((encstate', h1') : rest), Just x)

processLocalBackwardsRelay :: TorCircuit -> RelayCell -> IO ()
processLocalBackwardsRelay circ x =
  case x of
    RelayData{ relayStreamId = strmId, relayData = bstr } ->
      withMVar (circSockets circ) $ \ smap ->
        case Map.lookup strmId smap of
          Nothing ->
            circLog circ ("Dropping traffic to unknown stream " ++ show strmId)
          Just sock ->
            do state <- readMVar (tsState sock)
               unless (isJust state) $ writeChan (tsInChan sock) (Right bstr)

    RelayEnd{ relayStreamId = strmId, relayEndReason = rsn } ->
       modifyMVar_ (circSockets circ) $ \ smap ->
         case Map.lookup strmId smap of
           Nothing ->
             return smap
           Just sock ->
             do modifyMVar_ (tsState sock) (const (return (Just rsn)))
                writeChan (tsInChan sock) (Left rsn)
                return (Map.delete strmId smap)

    RelayConnected{ relayStreamId = tsStreamId } ->
      modifyMVar_ (circConnWaiters circ) $ \ cwaits ->
        case Map.lookup tsStreamId cwaits of
          Nothing ->
            do circLog circ ("CONNECTED without waiter?")
               return cwaits
          Just wait ->
            do let tsCircuit = circ
               tsState      <- newMVar Nothing
               tsInChan     <- newChan
               tsLeftover   <- newMVar S.empty
               tsReadWindow <- newMVar 500 -- See spec, 7.4, stream flow
               let sock = TorSocket { .. }
               modifyMVar_ (circSockets circ) $ \ socks ->
                 return (Map.insert tsStreamId sock socks)
               _ <- tryPutMVar wait (Right sock)
               return (Map.delete tsStreamId cwaits)

    RelaySendMe {} ->
      do circLog circ "SENDME"
         return ()

    RelayExtended {} ->
      void $ tryPutMVar (circExtendWaiter circ) x

    RelayTruncated {} ->
      do circLog circ ("TRUNCATED: " ++ show (relayTruncatedRsn x))
         return () -- FIXME

    RelayDrop {} ->
      return ()

    RelayResolved { relayStreamId = strmId } ->
      modifyMVar_ (circResolveWaiters circ) $ \ resolveds ->
        case Map.lookup strmId resolveds of
          Nothing ->
            do circLog circ ("Resolved unknown request.")
               return resolveds
          Just wait ->
            do _ <- tryPutMVar wait (relayResolvedAddrs x)
               return (Map.delete strmId resolveds)

    RelayExtended2 {} ->
      void $ tryPutMVar (circExtendWaiter circ) x

    _ ->
      circLog circ ("Unexpected relay cell on backward link.")

-- processForwardInput :: TorCircuit -> TorCell -> IO ()
-- processForwardInput = undefined

-- ----------------------------------------------------------------------------

resolveName :: TorCircuit -> String -> IO [(TorAddress, Word32)]
resolveName circ str =
  do strmId <- getNextStreamId circ
     resMV  <- newEmptyMVar
     modifyMVar_ (circResolveWaiters circ) $ \ m ->
       return (Map.insert strmId resMV m)
     writeCellOnCircuit circ (RelayResolve strmId str)
     takeMVar resMV

-- ----------------------------------------------------------------------------

data TorSocket = TorSocket {
       tsCircuit    :: TorCircuit
     , tsStreamId   :: Word16
     , tsState      :: MVar (Maybe RelayEndReason)
     , tsReadWindow :: MVar Int
     , tsInChan     :: Chan (Either RelayEndReason ByteString)
     , tsLeftover   :: MVar ByteString
     }

-- |Connect to the given address and port through the given circuit. The result
-- is a connection that can be used to read, write, and close the connection.
-- (This is equivalent to calling connectToHost' with True, True, and False for
-- the extra arguments.)
connectToHost :: TorCircuit -> TorAddress -> Word16 -> IO TorSocket
connectToHost tc a p = connectToHost' tc a p True True False

-- |Connect to the given address and port through the given circuit. The result
-- is a connection that can be used to read, write, and close the connection.
-- The booleans determine if an IPv4 connection is OK, an IPv6 connection is OK,
-- and whether IPv6 is preferred, respectively.
connectToHost' :: TorCircuit ->
                  TorAddress -> Word16 ->
                  Bool -> Bool -> Bool ->
                  IO TorSocket
connectToHost' circ addr port ip4ok ip6ok ip6pref =
  do strmId <- getNextStreamId circ
     resMV  <- newEmptyMVar
     modifyMVar_ (circConnWaiters circ) $ \ m ->
       return (Map.insert strmId resMV m)
     writeCellOnCircuit circ (RelayBegin strmId addr port ip4ok ip6ok ip6pref)
     throwLeft =<< takeMVar resMV
 where
  throwLeft (Left a)  = throwIO (userError a)
  throwLeft (Right x) = return x

-- |Write the given ByteString to the given Tor socket. Blocks until the entire
-- ByteString has been written out to the network. Will throw an error if the
-- socket has been closed.
torWrite :: TorSocket -> ByteString -> IO ()
torWrite sock block =
  do state <- readMVar (tsState sock)
     case state of
       Just reason ->
         throwIO (userError ("Write to closed socket: " ++ show reason))
       Nothing ->
         loop block
 where
  loop bstr
   | S.null bstr = return ()
   | otherwise   =
       do let (cur, rest) = S.splitAt 503 bstr
              strmId      = tsStreamId sock
          writeCellOnCircuit (tsCircuit sock) (RelayData strmId cur)
          loop rest

-- |Read the given number of bytes from the socket. Blocks until either the
-- entire buffer has been read or the socket closes for some reason. Will throw
-- an error if the socket was closed before the read starts.
torRead :: TorSocket -> Int -> IO L.ByteString
torRead sock amt =
  modifyMVar (tsLeftover sock) $ \ headBuf ->
    if S.length headBuf >= amt
       then do let (res, headBuf') = S.splitAt amt headBuf
               return (headBuf', L.fromStrict res)
       else do let amt' = amt - S.length headBuf
               res <- loop amt' [headBuf]
               return res
 where
  loop x acc =
    do nextBuf <- readChan (tsInChan sock)
       join $ modifyMVar (tsReadWindow sock) $ \ strmWindow ->
                do let newval = strmWindow - 1
                   putStrLn ("newval = " ++ show newval)
                   if newval <= 450
                      then return (newval + 50, sendMe)
                      else return (newval, return ())
       case nextBuf of
         Left err | all S.null acc ->
           do writeChan (tsInChan sock) nextBuf
              throwIO (userError ("Read from closed socket: " ++ show err))
         Left _ ->
           do writeChan (tsInChan sock) nextBuf
              return (S.empty, L.fromChunks (reverse acc))
         Right buf | S.length buf >= x ->
           do let (mine, leftover) = S.splitAt x buf
              return (leftover, L.fromChunks (reverse (mine:acc)))
         Right buf ->
           loop (x - S.length buf) (buf : acc)
  --
  sendMe =
    writeCellOnCircuit (tsCircuit sock) (RelaySendMe (tsStreamId sock))

torClose :: TorSocket -> RelayEndReason -> IO ()
torClose sock reason =
  do let strmId = tsStreamId sock
     modifyMVar_ (tsState sock) (const (return (Just reason)))
     modifyMVar_ (circSockets (tsCircuit sock)) (return . Map.delete strmId)
     writeCellOnCircuit (tsCircuit sock) (RelayEnd strmId reason)

-- ----------------------------------------------------------------------------

newtype EncryptionState = ES L.ByteString

instance Eq EncryptionState where
  (ES a) == (ES b) = (L.take 256 a) == (L.take 256 b)

instance Show EncryptionState where
  show (ES x) = "EncryptionState(" ++ simpleHex (L.toStrict (L.take 8 x)) ++ " ...)"

initEncryptionState :: AES128 -> EncryptionState
initEncryptionState k = ES (xorStream k)

encryptData :: EncryptionState -> ByteString -> (ByteString, EncryptionState)
encryptData (ES state) bstr =
  let (ebstr, state') = L.splitAt (fromIntegral (S.length bstr)) state
  in (xorBS (L.toStrict ebstr) bstr, ES state')

decryptData :: EncryptionState -> ByteString -> (ByteString, EncryptionState)
decryptData = encryptData

xorStream :: AES128 -> L.ByteString
xorStream k = L.fromChunks (go 0)
 where
  go :: Integer -> [ByteString]
  go x = ecbEncrypt k (i2ospOf_ 16 x) : go (plus1' x)
  --
  plus1' x = (x + 1) `mod` (2 ^ (128 :: Integer))

xorBS :: ByteString -> ByteString -> ByteString
xorBS a b = S.pack (S.zipWith xor a b)

-- ----------------------------------------------------------------------------

getNextStreamId :: TorCircuit -> IO Word16
getNextStreamId circ =
  do nextId <- modifyMVar (circRNG circ) (return . randWord16)
     let nextId' = fromIntegral nextId
     good   <- modifyMVar (circTakenStreamIds circ) $ \ set ->
                 if IntSet.member nextId' set || nextId == 0
                    then return (set, False)
                    else return (IntSet.insert nextId' set, True)
     if good
        then return nextId
        else getNextStreamId circ
 where
  randWord16 rng = swap (withRandomBytes rng 2 toWord16)
  toWord16 bs = fromIntegral (S.index bs 0) `shiftL` 8 +
                fromIntegral (S.index bs 1)

-- -----------------------------------------------------------------------------

startTAPHandshake :: RouterDesc -> TorRNG ->
                     (TorRNG, (PrivateNumber, ByteString))
startTAPHandshake rtr g = (g'', (x, egx))
 where
  (x, g')         = withDRG g (generatePrivate oakley2)
  PublicNumber gx = calculatePublic oakley2 x
  gxBS            = i2ospOf_ 128 gx
  nodePub         = routerOnionKey rtr
  (egx, g'')      = withDRG g' (hybridEncrypt True nodePub gxBS)

advanceTAPHandshake :: PrivateKey -> Word32 -> ByteString -> TorRNG ->
                       (TorRNG, (TorCell,
                                 (EncryptionState, Context SHA1),
                                 (EncryptionState, Context SHA1)))
advanceTAPHandshake privkey circId egx g = (g'', (created, f, b))
 where
  (y, g')         = withDRG g (generatePrivate oakley2)
  PublicNumber gy = calculatePublic oakley2 y
  gyBS            = i2ospOf_ 128 gy
  (gxBS, g'')     = withDRG g' (hybridDecrypt privkey egx)
  gx              = PublicNumber (os2ip gxBS)
  (kh, f, b)      = computeTAPValues y gx
  created         = Created circId (gyBS `S.append` kh)

completeTAPHandshake :: PrivateNumber -> ByteString ->
                        Either String ((EncryptionState, Context SHA1),
                                       (EncryptionState, Context SHA1))
completeTAPHandshake x rbstr
  | kh == kh' = Right (f, b)
  | otherwise = Left "Key agreement failure."
 where
  (gyBS, kh)   = S.splitAt 128 rbstr
  gy           = PublicNumber (os2ip gyBS)
  (kh', f, b)  = computeTAPValues x gy

computeTAPValues :: PrivateNumber -> PublicNumber ->
                    (ByteString, (EncryptionState, Context SHA1),
                                 (EncryptionState, Context SHA1))
computeTAPValues b ga = (L.toStrict kh, (encsf, fhash), (encsb, bhash))
 where
  SharedKey k0 = getShared oakley2 b ga
  (kh, rest1)  = L.splitAt 20 (kdfTor (i2ospOf_ 128 k0))
  (df,  rest2) = L.splitAt 20  rest1
  (db,  rest3) = L.splitAt 20  rest2
  (kf,  rest4) = L.splitAt 16  rest3
  (kb,  _)     = L.splitAt 16  rest4
  keyf         = throwCryptoError (cipherInit (L.toStrict kf))
  keyb         = throwCryptoError (cipherInit (L.toStrict kb))
  encsf        = initEncryptionState keyf
  encsb        = initEncryptionState keyb
  fhash        = hashUpdate hashInit (L.toStrict df)
  bhash        = hashUpdate hashInit (L.toStrict db)

kdfTor :: ByteString -> L.ByteString
kdfTor k0 = L.fromChunks (map kdfTorChunk [0..255])
  where kdfTorChunk x = sha1 (S.snoc k0 x)

-- -----------------------------------------------------------------------------

startNTorHandshake :: RouterDesc -> TorRNG ->
                     (TorRNG, Maybe (Curve25519Pair, ByteString))
startNTorHandshake router g0 =
  case routerNTorOnionKey router of
    Nothing ->
      (g0, Nothing)
    Just keyid ->
      let (pair@(bigX, _), g1) = withDRG g0 generate25519
          nodeid = routerFingerprint router
          client_pk = convert bigX
          bstr = S.concat [nodeid, keyid, client_pk]
      in (g1, Just (pair, bstr))

advanceNTorHandshake :: RouterDesc -> Curve.SecretKey ->
                        ByteString -> TorRNG ->
                        (TorRNG, Either String (ByteString,
                                                (EncryptionState, Context SHA1),
                                                (EncryptionState, Context SHA1)))
advanceNTorHandshake me littleB bstr0 g0
  | Nothing <- routerNTorOnionKey me =
      (g0, Left "Called advance, but I don't support NTor handshakes.")
  | (nodeid /= routerFingerprint me) || (Just keyid /= routerNTorOnionKey me) =
      (g0, Left "Called advance, but their fingerprint doesn't match me.")
  | Left err <- publicKey keyid =
      (g0, Left ("Couldn't decode bigB in advance: " ++ err))
  | Left err <- publicKey keyid =
      (g0, Left ("Couldn't decode bigX in advance: " ++ err))
  | otherwise = (g1, Right (outdata,fenc,benc))
 where
  (nodeid, bstr1)       = S.splitAt 20 bstr0
  (keyid,  xpub)        = S.splitAt 32 bstr1
  Right bigB            = publicKey keyid
  Right bigX            = publicKey xpub
  ((bigY, littleY), g1) = withDRG g0 generate25519
  secret_input          = S.concat [curveExp bigX littleY,
                                    curveExp bigX littleB,
                                    nodeid, convert bigB, convert bigX,
                                    convert bigY, protoid]
  key_seed              = hmacSha256 secret_input t_key
  verify                = hmacSha256 t_verify secret_input
  auth_input            = S.concat [verify, nodeid, convert bigB, convert bigY,
                                    convert bigX, protoid, S8.pack "Server"]
  server_pk             = convert bigY
  auth                  = hmacSha256 t_mac auth_input
  --
  outdata               = S.concat [server_pk, auth]
  (fenc, benc)          = computeNTorValues key_seed

completeNTorHandshake :: RouterDesc -> Curve25519Pair -> ByteString ->
                         Either String ((EncryptionState, Context SHA1),
                                        (EncryptionState, Context SHA1))
completeNTorHandshake router (bigX, littleX) bstr
  | Nothing <- routerNTorOnionKey router = Left "Internal error complete/ntor"
  | Left err <- publicKey public_pk      = Left ("Couldn't decode bigY: "++err)
  | Left err <- publicKey server_ntorid  = Left ("Couldn't decode bigB: "++err)
  | auth /= auth'                        = Left ("Authorization codes don't match: " ++ simpleHex auth ++ " versus " ++ simpleHex auth')
  | otherwise                            = Right res
 where
  nodeid             = routerFingerprint router
  (public_pk, auth)  = S.splitAt 32 bstr
  Just server_ntorid = routerNTorOnionKey router
  Right bigY         = publicKey public_pk
  Right bigB         = publicKey server_ntorid
  secret_input       = S.concat [curveExp bigY littleX, curveExp bigB littleX,
                                 nodeid, convert bigB, convert bigX, convert bigY,
                                 protoid]
  key_seed           = hmacSha256 secret_input t_key
  verify             = hmacSha256 t_verify secret_input
  auth_input         = S.concat [verify, nodeid, convert bigB, convert bigY,
                                 convert bigX, protoid, S8.pack "Server"]
  auth'              = hmacSha256 t_mac auth_input
  res                = computeNTorValues key_seed

curveExp :: Curve.PublicKey -> Curve.SecretKey -> ByteString
curveExp a b = convert (dh a b)

type Curve25519Pair = (Curve.PublicKey, Curve.SecretKey)

generate25519 :: MonadRandom m => m Curve25519Pair
generate25519 =
  do bytes <- getRandomBytes 32
     case secretKey (bytes :: ByteString) of
       Left err ->
         fail ("Couldn't convert to a secret key: " ++ show err)
       Right privKey ->
         do let pubKey = toPublic privKey
            return (pubKey, privKey)

computeNTorValues :: ByteString -> ((EncryptionState, Context SHA1),
                                    (EncryptionState, Context SHA1))
computeNTorValues key_seed = ((encsf, fhash), (encsb, bhash))
 where
  bstr0       = kdfRFC5869 key_seed
  (df, bstr1) = L.splitAt 20 bstr0
  (db, bstr2) = L.splitAt 20 bstr1
  (kf, bstr3) = L.splitAt 16 bstr2
  (kb, _    ) = L.splitAt 16 bstr3
  -- FIXME: We should take a final DIGEST_LEN bytes here "for use in the
  -- place of KH in the hidden service protocol."
  keyf         = throwCryptoError (cipherInit (L.toStrict kf))
  keyb         = throwCryptoError (cipherInit (L.toStrict kb))
  encsf        = initEncryptionState keyf
  encsb        = initEncryptionState keyb
  fhash        = hashUpdate hashInit (L.toStrict df)
  bhash        = hashUpdate hashInit (L.toStrict db)

kdfRFC5869 :: ByteString -> L.ByteString
kdfRFC5869 kseed = L.fromChunks (map kn [1..250])
 where
  kn i
   | i  < 1    = error "Internal error, kdfRFC5859"
   | i == 1    = hmacSha256 (m_expand `S.snoc` 1) kseed
   | otherwise = hmacSha256 (S.concat [kn (i-1),m_expand,S.singleton i]) kseed

hmacSha256 :: (ByteArrayAccess key, ByteArray message, ByteArray res) =>
              key -> message -> res
hmacSha256 k m = convert res
 where res = hmac k m :: HMAC SHA256

protoid, t_mac, t_key, t_verify, m_expand :: ByteString
protoid               = S8.pack "ntor-curve25519-sha256-1"
t_mac                 = protoid `S.append` S8.pack ":mac"
t_key                 = protoid `S.append` S8.pack ":key_extract"
t_verify              = protoid `S.append` S8.pack ":verify"
m_expand              = protoid `S.append` S8.pack ":key_expand"

-- -- -----------------------------------------------------------------------------
-- 
-- -- This handler is called when we receive data from an earlier link in the
-- -- circuit. Thus, traffic we receive is moving forward through the network.
-- _forwardRelayHandler :: (String -> IO ()) -> TorRelay -> TorCell -> IO ()
-- _forwardRelayHandler llog circ cell =
--   case cell of
--     Relay _ body      -> forwardRelay Relay      body
--     RelayEarly _ body -> forwardRelay RelayEarly body
--     Destroy _ reason  -> llog ("Relay destroyed: " ++ show reason)
--     _                 -> llog ("Spurious message across relay.")
--  where
--   forwardRelay builder body =
--     do (encstate, hashstate) <- takeMVar (relayForwardCryptoData circ)
--        let (body', encstate') = decryptData encstate body
--        case runGetOrFail (parseRelayCell hashstate) (L.fromStrict body') of
--          Left _ ->
--            do putMVar (relayForwardCryptoData circ) (encstate', hashstate)
--               forward builder body'
--          Right (_, _, (x, hashstate')) ->
--            do putMVar (relayForwardCryptoData circ) (encstate', hashstate')
--               process x
--   --
--   forward builder bstr =
--     do fstate <- takeMVar (relayForwardStates circ)
--        case fstate of
--          ForwardLink{} ->
--             do linkWrite (flLink fstate) (builder (flCircuitId fstate) bstr)
--                putMVar (relayForwardStates circ) fstate
--          ForwardExtending{} ->
--             do putMVar (relayForwardStates circ) ForwardDeadEnd
--                let dst = Destroy (relayBackwardCircId circ) TorProtocolViolation
--                linkWrite (relayBackwardLink circ) dst
--                --endCircuit (relayBackwardLink circ) (relayBackwardCircId circ)
--          ForwardExit{} ->
--             do putMVar (relayForwardStates circ) ForwardDeadEnd
--                let dst = Destroy (relayBackwardCircId circ) TorProtocolViolation
--                linkWrite (relayBackwardLink circ) dst
--                --endCircuit (relayBackwardLink circ) (relayBackwardCircId circ)
--          ForwardDeadEnd ->
--             return ()
--   --
--   process RelayBegin{}    = putStrLn "RELAY_BEGIN"
--   process RelayData{}     = putStrLn "RELAY_DATA"
--   process RelayEnd{}      = putStrLn "RELAY_END"
--   process RelayExtend{}   = putStrLn "RELAY_DATA"
--   process RelayTruncate{} = putStrLn "RELAY_TRUNCATE"
--   process RelayDrop{}     = putStrLn "RELAY_DROP"
--   process RelayResolve{}  = putStrLn "RELAY_RESOLVE"
--   process RelayExtend2{}  = putStrLn "RELAY_EXTEND2"
--   process _               = return ()
-- 

