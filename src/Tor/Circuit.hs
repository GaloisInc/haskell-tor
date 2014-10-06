module Tor.Circuit(
         createCircuit
       , extendCircuit
       , destroyCircuit
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
     , circExtendWaiter       :: MVar (Either DestroyReason ByteString)
     , circForwardCryptoData  :: MVar ([SHA1State], [EncryptionState], Word64)
     , circBackwardCryptoData :: MVar ([SHA1State], [EncryptionState])
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

-- Destroy the circuit, sending the given reason upstream.
destroyCircuit :: TorCircuit -> DestroyReason -> IO ()
destroyCircuit circ reason =
  do _ <- tryPutMVar (circExtendWaiter circ) (Left reason)
     let circId = circCircuitId circ
         link   = circForwardLink circ
     writeCell link (Destroy circId reason)
     endCircuit link circId

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
       case initres of
         Left destReason ->
           return (Left ("Could not create initial link: " ++ show destReason))
         Right rbstr ->
              -- FIXME: Should be checking for degenerate cases.
           do let (ok, keyf, fhash, keyb, bhash) = completeTAPHandshake x rbstr
              if ok
                 then do fcdMV   <- newMVar ([fhash], [keyf], 0)
                         bcdMV   <- newMVar ([bhash], [keyb])
                         ewMV    <- newEmptyMVar
                         let circ = TorCircuit link circId ewMV fcdMV bcdMV
                             handler' = backwardRelayHandler torst circ
                         modifyCircuitHandler link circId handler'
                         return (Right circ)
                 else return (Left "Key agreement failure.")
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
     case res of
       Left drsn ->
         return (Left (show drsn))
       Right rbstr ->
         do let (ok, keyf, fhash, keyb, bhash) = completeTAPHandshake x rbstr
            if ok
               then do (fhs, fks, cntr) <- takeMVar (circForwardCryptoData circ)
                       let fhs' = fhash : fhs -- fhs ++ [fhash]
                           fks' = keyf : fks -- fks ++ [keyf]
                       (bhs, bks) <- takeMVar (circBackwardCryptoData circ)
                       let bhs' = bhs ++ [bhash]
                           bks' = bks ++ [keyb]
                       putMVar (circForwardCryptoData circ)  (fhs', fks', cntr)
                       putMVar (circBackwardCryptoData circ) (bhs', bks')
                       logMsg torst ("Extended circuit to " ++ routerIPv4Address nextRouter)
                       return (Right ())
               else return (Left "Key agreement failure.")
 where
  extendCell skin = RelayExtend {
      relayStreamId      = 0
    , relayExtendAddress = IP4 (routerIPv4Address nextRouter)
    , relayExtendPort    = routerORPort nextRouter
    , relayExtendSkin    = skin
    , relayExtendIdent   = keyHash' sha1 (routerSigningKey nextRouter)
    }

-- -----------------------------------------------------------------------------

writeCellOnCircuit :: TorCircuit -> RelayCell -> IO ()
writeCellOnCircuit circ relay =
  do (sha1ss, keys, cellCount) <- takeMVar (circForwardCryptoData circ)
     let (lastState:restStates) = sha1ss
         (bstr,lastState')      = renderRelayCell lastState relay
         (encbstr, keys')       = encryptWithKeys bstr keys
         builder                = pickBuilder relay
     writeCell (circForwardLink circ) (builder (circCircuitId circ) encbstr)
     let sha1ss' = lastState' : restStates
     putMVar (circForwardCryptoData circ) (sha1ss', keys', cellCount + 1)
 where
  pickBuilder RelayExtend{}  = RelayEarly
  pickBuilder RelayExtend2{} = RelayEarly
  pickBuilder _              = RelayEarly
  --
  encryptWithKeys bstr [] = (bstr, [])
  encryptWithKeys bstr (encstate:rstates) =
    let (bstr', encstate') = encryptData encstate bstr
        (res,   rstates')  = encryptWithKeys bstr' rstates
    in (res, encstate' : rstates') 

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
      do (hashes, keys) <- takeMVar (circBackwardCryptoData circ)
         (keys', hashes', res) <- decryptUntilClean body keys hashes
         putMVar (circBackwardCryptoData circ) (hashes', keys')
         case res of
           Nothing ->
             do logMsg torst ("Relay destined for upstream consumer.")
                BS.writeFile "testblob" body
                circSendUpstream circ (Relay cnum body)
           Just x ->
               case x of
                 RelayData{} ->
                   logMsg torst ("Recieved (B) RELAY_DATA")
                 RelayEnd{} ->
                   logMsg torst ("Recieved (B) RELAY_END")
                 RelayConnected{} ->
                   logMsg torst ("Received (B) RELAY_CONNECTED")
                 RelaySendMe{} ->
                   logMsg torst ("Received (B) RELAY_SENDME")
                 RelayExtended{} ->
                   do ok <- tryPutMVar (circExtendWaiter circ)
                                       (Right (relayExtendedData x))
                      unless ok $
                        do destroyCircuit circ InternalError
                           logMsg torst ("Received RELAY_EXTENDED but not " ++
                                         "extending relay.")
                 RelayTruncated{} ->
                   logMsg torst ("Received (B) RELAY_TRUNCATED: " ++ show (relayTruncatedRsn x))
                 RelayDrop{} ->
                   logMsg torst ("Received (B) RELAY_DROP")
                 RelayResolved{} ->
                   logMsg torst ("Received (B) RELAY_RESOLVED")
                 RelayExtended2{} ->
                   logMsg torst ("Received (B) RELAY_EXTENDED2")
                 _ ->
                   logMsg torst ("Weird message on backward stream: " ++show x)
    RelayEarly cnum body ->
      -- Treat RelayEarly as Relay. This could be a problem. FIXME?
      backwardRelayHandler torst circ (Relay cnum body)
    Destroy _ reason ->
      do logMsg torst ("Circuit destroyed: " ++ show reason)
         destroyCircuit circ reason
    _ ->
      logMsg torst ("Spurious message along relay.")

decryptUntilClean :: ByteString -> [EncryptionState] -> [SHA1State] ->
                     IO ([EncryptionState], [SHA1State], Maybe RelayCell)
decryptUntilClean _    []                            [] =
  return ([], [], Nothing)
decryptUntilClean _    []                            _  =
  fail "DecryptUntilClean with unevent arguments."
decryptUntilClean _    _                             [] =
  fail "DecryptUntilClean with unevent arguments. (2)"
decryptUntilClean bstr (encstate:rstates) (h1:rhashes) =
  do let (bstr', encstate') = decryptData encstate bstr
     case runGetOrFail (parseRelayCell h1) bstr' of
       Left _ ->
         do (rstates', rhashes', res) <- decryptUntilClean bstr' rstates rhashes
            return (encstate' : rstates', h1 : rhashes', res)
       Right (_, _, (x, h1')) ->
         return (encstate' : rstates, h1' : rhashes, Just x)

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

completeTAPHandshake :: Integer -> ByteString ->
                        (Bool, EncryptionState, SHA1State,
                               EncryptionState, SHA1State)
completeTAPHandshake x rbstr = (kh == kh', encsf, fhash, encsb, bhash)
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


