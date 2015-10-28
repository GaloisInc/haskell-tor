{-# LANGUAGE RecordWildCards #-}
module Tor.Circuit(
         TorCircuit
       , createCircuit
       , acceptCircuit
       , destroyCircuit
       , extendCircuit
       --
       , resolveName
       --
       , TorSocket(..)
       , connectToHost
       , connectToHost'
       , torRead
       , torWrite
       , torClose
       )
 where

import Control.Concurrent
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
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import Data.Either
import Data.IntSet(IntSet)
import qualified Data.IntSet as IntSet
import Data.Maybe
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Tuple
import Data.Word
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.HybridCrypto
import Tor.Link
import Tor.Link.DH
import Tor.RNG
import Tor.RouterDesc

-- -----------------------------------------------------------------------------

data TorCircuit = TorCircuit {
       circForwardLink     :: Maybe TorLink
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

createCircuit :: MVar TorRNG -> (String -> IO ()) ->
                 TorLink -> RouterDesc -> Word32 ->
                 IO TorCircuit
createCircuit circRNG circLog link firstRouter circId =
  do x <- modifyMVar circRNG (return . generateLocal')
     let PublicNumber gx = calculatePublic oakley2 x
         gxBS = i2ospOf_ 128 gx
     let nodePub = routerOnionKey firstRouter
     egx <- hybridEncrypt True nodePub gxBS
     linkWrite link (Create circId egx)
     createResp <- linkRead link circId
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
                   let circForwardLink = Just link
                   let circ = TorCircuit { .. }
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
 where
  failLog str = circLog str >> throwIO (userError str)
  runBackward circ =
    forever $ do next <- linkRead link circId
                 processBackwardInput circ next

acceptCircuit :: TorLink -> IO TorCircuit
acceptCircuit = error "acceptCircuit"

-- |Destroy a circuit, and all the streams and computations running through it.
destroyCircuit :: TorCircuit -> DestroyReason -> IO ()
destroyCircuit circ rsn =
  do ts <- modifyMVar (circState circ) $ \ state ->
            case state of
              Left _ -> return (state, [])
              Right threads ->
                do mapM_ killSockets =<< readMVar (circSockets circ)
                   mapM_ killConnWaiters =<< readMVar (circConnWaiters circ)
                   mapM_ killResWaiters =<< readMVar (circResolveWaiters circ)
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
     x <- modifyMVar (circRNG circ) (return . generateLocal')
     let PublicNumber gx = calculatePublic oakley2 x
         gxBS = i2ospOf_ 128 gx
     egx <- hybridEncrypt True (routerOnionKey nextRouter) gxBS
     writeCellOnCircuit circ (extendCell egx)
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
  case circForwardLink circ of
    Nothing ->
      throwIO (userError "Attempt to write cell on circuit w/o forward link.")
    Just link ->
      do keysnhashes <- takeMVar (circForeCryptoData circ)
         let (cell, keysnhashes') = synthesizeRelay keysnhashes
         linkWrite link (pickBuilder relay (circId circ) cell)
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
               return (Map.delete strmId smap)

    RelayConnected{ relayStreamId = tsStreamId } ->
      modifyMVar_ (circConnWaiters circ) $ \ cwaits ->
        case Map.lookup tsStreamId cwaits of
          Nothing ->
            do circLog circ ("CONNECTED without waiter?")
               return cwaits
          Just wait ->
            do let tsCircuit = circ
               tsState    <- newMVar Nothing
               tsInChan   <- newChan
               tsLeftover <- newMVar S.empty
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
      do circLog circ "TRUNCATED"
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
       tsCircuit  :: TorCircuit
     , tsStreamId :: Word16
     , tsState    :: MVar (Maybe RelayEndReason)
     , tsInChan   :: Chan (Either RelayEndReason ByteString)
     , tsLeftover :: MVar ByteString
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
  do state <- readMVar (tsState sock)
     case state of
       Just reason ->
         throwIO (userError ("Read from closed socket: " ++ show reason))
       Nothing ->
         -- FIXME: End of connection issues.
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
       case nextBuf of
         Left _ ->
           return (S.empty, L.fromChunks (reverse acc))
         Right buf | S.length buf >= x ->
           do let (mine, leftover) = S.splitAt x buf
              return (leftover, L.fromChunks (reverse (mine:acc)))
         Right buf ->
           loop (x - S.length buf) (buf : acc)

torClose :: TorSocket -> RelayEndReason -> IO ()
torClose sock reason =
  do let strmId = tsStreamId sock
     modifyMVar_ (tsState sock) (const (return (Just reason)))
     modifyMVar_ (circSockets (tsCircuit sock)) (return . Map.delete strmId)
     writeCellOnCircuit (tsCircuit sock) (RelayEnd strmId reason)

-- ----------------------------------------------------------------------------

newtype EncryptionState = ES L.ByteString

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

generateLocal' :: TorRNG -> (TorRNG, PrivateNumber)
generateLocal' g = swap (withDRG g (generatePrivate oakley2))

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
computeTAPValues b ga = (kh, (encsf, fhash), (encsb, bhash))
 where
  SharedKey k0 = getShared oakley2 b ga
  (kh, rest1)  = S.splitAt 20 (kdfTor (i2ospOf_ 128 k0))
  (df,  rest2) = S.splitAt 20  rest1
  (db,  rest3) = S.splitAt 20  rest2
  (kf,  rest4) = S.splitAt 16  rest3
  (kb,  _)     = S.splitAt 16  rest4
  keyf         = throwCryptoError (cipherInit kf)
  keyb         = throwCryptoError (cipherInit kb)
  encsf        = initEncryptionState keyf
  encsb        = initEncryptionState keyb
  fhash        = hashUpdate hashInit df
  bhash        = hashUpdate hashInit db

kdfTor :: ByteString -> ByteString
kdfTor k0 = S.concat (map kdfTorChunk [0..255])
  where kdfTorChunk x = sha1 (S.snoc k0 x)


-- data TorEntrance = TorEntrance {
--       circForwardLink        :: TorLink
--     , circCircuitId          :: Word32
--     , circNextStreamId       :: MVar Word16
--     , circExtendWaiter       :: MVar ByteString
--     , circResolveWaiters     :: MVar (Map Word16 (MVar [(TorAddress, Word32)]))
--     , circConnectionWaiters  :: MVar (Map Word16 (MVar ConnectionResp))
--     , circDataBuffers        :: MVar (Map Word16 (MVar ByteString))
--     , circForwardCryptoData  :: MVar [(EncryptionState, Context SHA1)]
--     , circBackwardCryptoData :: MVar [(EncryptionState, Context SHA1)]
--     }
-- 
-- data ForwardState = ForwardLink {
--                       flLink                :: TorLink
--                     , flCircuitId           :: Word32
--                     }
--                   | ForwardExtending
--                   | ForwardExit {
--                     }
--                   | ForwardDeadEnd
-- 
-- 
-- data TorRelay = TorRelay {
--       relayBackwardLink       :: TorLink
--     , relayBackwardCircId     :: Word32
--     , relayForwardCryptoData  :: MVar (EncryptionState, Context SHA1)
--     , _relayBackwardCryptoData :: MVar (EncryptionState, Context SHA1)
--     , relayForwardStates      :: MVar ForwardState
--     }
-- 
-- -- Send a cell downstream in the circuit, in the cirection of the CREATE
-- -- request, away from the originator of the circuit. If there is no downstream
-- -- (i.e., we're the exit node), then this triggers the destruction of the
-- -- circuit.
-- -- circSendDownstream :: TorEntrance -> TorCell -> IO ()
-- -- circSendDownstream = error "circSendDownstream"
-- 
-- -- Send a cell upstream in the circuit, towards the originator of the circuit.
-- -- If there is no upstream circuit (i.e., we're the origination point), then
-- -- this triggers the destruction of the circuit.
-- circSendUpstream :: TorEntrance -> TorCell -> IO ()
-- circSendUpstream _ _ =
--   do putStrLn "WARNING: circSendUpstream"
--      _ <- undefined TorRelay
--      return ()
-- 
-- -- -----------------------------------------------------------------------------
-- 
-- -- Process input coming from downstream back upstream.
-- processBackwardInput :: MVar [(EncryptionState, Context SHA1)] ->
--                         MVar RelayCell ->
--                         MVar (Map Word16 (Maybe RelayEndReason, L.ByteString))->
--                         (String -> IO ()) ->
--                         TorCell ->
--                         IO ()
-- processBackwardInput bcdMV extendMV strmMapMV llog cell =
--   case cell of
--     Relay circId body ->
--       do clearBody <- modifyMVar bcdMV (return . decryptUntilClean body)
--          case clearBody of
--            Nothing -> circSendUpstream undefined (Relay circId body)
--            Just x ->
--              case x of
--                RelayData { relayStreamId = strmId, relayData = bstr } ->
--                  modifyMVar_ strmMapMV $ \ map ->
--                    case Map.lookup strmId map of
--                      Nothing ->
--                        llog ("Dropping traffic to unknown stream "++show strmId)
--                      Just (Nothing, bstr) ->
--                        Map.insert strmId (True, bstr `S.append` bstr) map
--                      Just (Just _, _) ->
--                        llog ("Dropping traffic to closed stream "++show strmIf)
--                RelayEnd  { relayStreamId = strmId, relayEndReason = rsn } ->
--                  modifyMVar_ strmMapMV $ \ map ->
--                    case Map.lookup strmId map of
--                      Just (Nothing, bstr) ->
--                        Map.insert strmId (Just rsn, bstr) map
--                      _ ->
--                        return ()
--                RelayConnected { relayStreamId = strmId } ->
--                  modifyMVar_ strmMapMV $ \ map ->
--                    Map.insert strmId (Nothing, L.empty) map
--                RelaySendMe { } ->
--                  return ()
--                RelayExtended {} ->
--                  do res <- tryPutMVar extendMV x
--                     unless res $ llog ("Failed to write to extendMV!")
--                RelayTruncated {} ->
--                  undefined
--                RelayDrop {} ->
--                  return ()
--                RelayResolved { relayStreamId = strmId } ->
--                  modifyMVar_ (circResolveWaiters circ) $ \ rslvs ->
--                    case Map.lookup strmId rslvs of
--                      Nothing ->
--                        llog ("Resolved unknown request " ++ show strmId)
--                      Just mvar ->
--                        do _ <- tryPutMVar mvar (relayResolvedAddrs x)
--                           return (Map.delete strmId rslvs)
--                RelayExtended2 {} ->
--                  do res <- tryPutMVar extendMV x
--                     unless res $ llog ("Failed to write to extendMV!")
--                _                ->
--                  llog ("[BACKWARDS] Ignoring weird relay cell: " ++ show x)
--     RelayEarly circId body ->
--       -- Treat RelayEarly as Relay. This could be a problem. FIXME?
--       processBackwardInput bcdMV llog (Relay circId body)
--     Destroy _ reason ->
--       undefined
--     _ ->
--       llog ("Spurious message along relay.")
-- 
-- -- |Given a circuit, extend the end to the given router.
-- extendCircuit :: MVar TorRNG -> (String -> IO ()) ->
--                  TorEntrance -> RouterDesc ->
--                  IO (Either String ())
-- extendCircuit rngMV _llog circ nextRouter =
--   do x <- modifyMVar rngMV (return . generateLocal')
--      let PublicNumber gx = calculatePublic oakley2 x
--          gxBS = i2ospOf_ 128 gx
--      egx <- hybridEncrypt True (routerOnionKey nextRouter) gxBS
--      writeCellOnCircuit circ (extendCell egx)
--      res <- takeMVar (circExtendWaiter circ)
--      case completeTAPHandshake x res of
--        Left err -> return (Left err)
--        Right (fencstate, bencstate) ->
--          do modifyMVar_ (circForwardCryptoData circ) $ \ rest ->
--               return (rest ++ [fencstate])
--             modifyMVar_ (circBackwardCryptoData circ) $ \ rest ->
--               return (rest ++ [bencstate])
--             return (Right ())
--  where
--   extendCell skin = RelayExtend {
--       relayStreamId      = 0
--     , relayExtendAddress = IP4 (routerIPv4Address nextRouter)
--     , relayExtendPort    = routerORPort nextRouter
--     , relayExtendSkin    = skin
--     , relayExtendIdent   = keyHash' sha1 (routerSigningKey nextRouter)
--     }
-- 
-- -- -----------------------------------------------------------------------------
-- 
-- -- buildRelay :: TorState ls s -> TorLink -> Word32 -> ByteString -> IO ()
-- -- buildRelay torst link circId egx = catch buildInCircuit' internalError
-- --  where
-- --   buildInCircuit' =
-- --     do (_, PrivKeyRSA nodePriv) <- getOnionCredentials torst
-- --        gxBS                     <- hybridDecrypt nodePriv egx
-- --        y                        <- withRNG torst generateLocal'
-- --        let gx              = PublicNumber (os2ip gxBS)
-- --            PublicNumber gy = calculatePublic oakley2 y
-- --            gyBS            = i2ospOf_ 128 gy
-- --            (kh, f, b)      = computeTAPValues y gx
-- --            resp            = gyBS `S.append` kh
-- --        fMV  <- newMVar f
-- --        bMV  <- newMVar b
-- --        flMV <- newMVar ForwardDeadEnd
-- --        let relay = TorRelay link circId fMV bMV flMV
-- --        modifyCircuitHandler link circId (forwardRelayHandler torst relay)
-- --        writeCell link (Created circId resp)
-- --   --
-- --   internalError :: SomeException -> IO ()
-- --   internalError e =
-- --     do logMsg torst ("Internal error building circuit: " ++ show e)
-- --        writeCell link (Destroy circId InternalError)
-- -- 
-- -- buildRelayFast :: TorState ls s -> TorLink -> Word32 -> ByteString -> IO ()
-- -- buildRelayFast = error "FIXME: buildRelayFast"
-- 
-- -- -----------------------------------------------------------------------------
-- 
-- -- Destroy the circuit, sending the given reason upstream.
-- destroyCircuit :: TorEntrance -> DestroyReason -> IO ()
-- destroyCircuit circ reason =
--   do -- _ <- tryPutMVar (circExtendWaiter circ) (Left reason)
--      let circId = circCircuitId circ
--          link   = circForwardLink circ
--      linkWrite link (Destroy circId reason)
--      --endCircuit link circId
-- 
-- -- -----------------------------------------------------------------------------
-- 
-- data TorConnection = TorConnection {
--        torWrite :: ByteString -> IO ()
--      , torRead  :: Int -> IO ByteString
--      , torClose :: IO ()
--      }
-- 
-- -- |Resolve the given name anonymously on the given circuit. In some cases,
-- -- you may receive error values amongst the responses. The Word32 provided with
-- -- each response is a TTL for that response.
-- resolveName :: TorEntrance -> String -> IO [(TorAddress, Word32)]
-- resolveName circ str =
--   do strmId <- getNextStreamId circ
--      resMV  <- newEmptyMVar
--      modifyMVar_ (circResolveWaiters circ) $ \ m ->
--        return (Map.insert strmId resMV m)
--      writeCellOnCircuit circ (RelayResolve strmId str)
--      takeMVar resMV
-- 
-- -- |Connect to the given address and port through the given circuit. The result
-- -- is a connection that can be used to read, write, and close the connection.
-- -- (This is equivalent to calling connectToHost' with True, True, and False for
-- -- the extra arguments.
-- connectToHost :: TorEntrance -> TorAddress -> Word16 -> IO TorConnection
-- connectToHost tc a p = connectToHost' tc a p True True False
-- 
-- -- |Connect to the given address and port through the given circuit. The result
-- -- is a connection that can be used to read, write, and close the connection.
-- -- The booleans determine if an IPv4 connection is OK, an IPv6 connection is OK,
-- -- and whether IPv6 is preferred, respectively.
-- connectToHost' :: TorEntrance ->
--                   TorAddress -> Word16 ->
--                   Bool -> Bool -> Bool ->
--                   IO TorConnection
-- connectToHost' circ addr port ip4ok ip6ok ip6pref =
--   do strmId <- getNextStreamId circ
--      resMV  <- newEmptyMVar
--      modifyMVar_ (circConnectionWaiters circ) $ \ m ->
--        return (Map.insert strmId resMV m)
--      writeCellOnCircuit circ (RelayBegin strmId addr port ip4ok ip6ok ip6pref)
--      throwLeft =<< takeMVar resMV
--  where
--   throwLeft (Left a)  = throwIO a
--   throwLeft (Right x) = return x
-- 
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
-- -- This handler is called when we receive data from the next link in the
-- -- circuit. Thus, traffic we receive is moving backwards through the network.
-- backwardRelayHandler :: (String -> IO ()) -> TorEntrance -> TorCell -> IO ()
-- backwardRelayHandler llog circ cell =
--   case cell of
--     Relay cnum body ->
--       do keysnhashes <- takeMVar (circBackwardCryptoData circ)
--          let (keysnhashes', res) = decryptUntilClean body keysnhashes
--          putMVar (circBackwardCryptoData circ) keysnhashes'
--          case res of
--            Nothing -> circSendUpstream circ (Relay cnum body)
--            Just x ->
--              case x of
--                RelayData{}      -> addDataBlock x (relayData x)
--                RelayEnd{}       -> do destroyConnection x    (relayEndReason x)
--                                       destroyCircuit    circ CircuitDestroyed
--                RelayConnected{} -> finalizeConnect x
--                RelaySendMe{}    -> llog ("Received (B) RELAY_SENDME")
--                RelayExtended{}  -> continueExtend (relayExtendedData x)
--                RelayTruncated{} -> answerResolve x []
--                RelayDrop{}      -> return ()
--                RelayResolved{}  -> answerResolve x (relayResolvedAddrs x)
--                RelayExtended2{} -> return () -- FIXME
--                _                -> return ()
--     RelayEarly cnum body ->
--       -- Treat RelayEarly as Relay. This could be a problem. FIXME?
--       backwardRelayHandler llog circ (Relay cnum body)
--     Destroy _ reason ->
--       do llog ("Circuit destroyed: " ++ show reason)
--          destroyCircuit circ reason
--     _ ->
--       llog ("Spurious message along relay.")
--  where
--   addDataBlock x block =
--     do mmv <- getDeleteFromMap (circDataBuffers circ) (relayStreamId x)
--        case mmv of
--          Nothing -> return ()
--          Just mv -> do orig <- takeMVar mv
--                        putMVar mv (orig `S.append` block)
--   getDeleteFromMap mapMV key =
--     modifyMVar mapMV $ \ mvmap ->
--       return (Map.delete key mvmap, Map.lookup key mvmap)
--   answerResolve x result =
--     do mmv <- getDeleteFromMap (circResolveWaiters circ) (relayStreamId x)
--        case mmv of
--          Nothing -> return ()
--          Just mv -> putMVar mv result
--   --
--   continueExtend extdata =
--     do ok <- tryPutMVar (circExtendWaiter circ) extdata
--        unless ok $ destroyCircuit circ InternalError
--   --
--   destroyConnection x reason =
--    do mmv <- getDeleteFromMap (circConnectionWaiters circ) (relayStreamId x)
--       case mmv of
--         Nothing -> return ()
--         Just mv -> putMVar mv (Left reason)
--       _ <- getDeleteFromMap (circDataBuffers circ) (relayStreamId x)
--       return ()
--   --
--   finalizeConnect x =
--    do mmv <- getDeleteFromMap (circConnectionWaiters circ) (relayStreamId x)
--       case mmv of
--         Nothing -> return ()
--         Just mv ->
--           do res <- buildConnection circ (relayStreamId x)
--              putMVar mv (Right res)
--   --
--   decryptUntilClean :: ByteString -> [(EncryptionState, Context SHA1)] ->
--                        ([(EncryptionState, Context SHA1)], Maybe RelayCell)
--   decryptUntilClean _    []                    = ([], Nothing)
--   decryptUntilClean bstr ((encstate, h1):rest) =
--     let (bstr', encstate') = decryptData encstate bstr
--     in case runGetOrFail (parseRelayCell h1) (L.fromStrict bstr') of
--          Left _ ->
--            let (rest', res) = decryptUntilClean bstr' rest
--            in ((encstate', h1) : rest', res)
--          Right (_, _, (x, h1')) ->
--            (((encstate', h1') : rest), Just x)
-- 
-- -- -----------------------------------------------------------------------------
-- 
-- buildConnection :: TorEntrance -> Word16 -> IO TorConnection
-- buildConnection circ strmId =
--   do readMV <- newMVar S.empty
--      modifyMVar_ (circDataBuffers circ) $ \ dbmap ->
--        return (Map.insert strmId readMV dbmap)
--      return TorConnection{
--               torRead  = readBytes readMV
--             , torWrite = writeBytes circ strmId
--             , torClose = closeConnection circ strmId
--             }
-- 
-- readBytes :: MVar ByteString -> Int -> IO ByteString
-- readBytes bstrMV total = S.concat `fmap` loop total
--  where
--   loop 0   = return []
--   loop amt = do buffer <- takeMVar bstrMV
--                 let (res, rest) = S.splitAt amt buffer
--                 putMVar bstrMV rest
--                 (res :) `fmap` loop (amt - S.length res)
-- 
-- writeBytes :: TorEntrance -> Word16 -> ByteString -> IO ()
-- writeBytes circ strmId bstr
--   | S.null bstr = return ()
--   | otherwise    =
--       do let (cur, rest) = S.splitAt 503 bstr
--          writeCellOnCircuit circ (RelayData strmId cur)
--          writeBytes circ strmId rest
-- 
-- closeConnection :: TorEntrance -> Word16 -> IO ()
-- closeConnection c strmId = writeCellOnCircuit c (RelayEnd strmId ReasonDone)
