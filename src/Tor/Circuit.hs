-- |Low-level routines for generating, extending, and destroying circuits. We
-- strongly recommend not using this module unless you have a very good reason.
-- You should probably just use the high-level Tor module or the CircuitManager
-- module instead.
{-# LANGUAGE RecordWildCards #-}
module Tor.Circuit(
       -- * High-level type for Tor circuits that originate at the current
       -- node, and operations upon them.
         OriginatedCircuit
       , createCircuit
       , destroyCircuit
       , extendCircuit
       -- * High-level type and operations on circuits that are passing through
       -- or exiting at this node.
       , TransverseCircuit
       , acceptCircuit
       , destroyTransverse
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
       , CryptoData
       , Curve25519Pair
       , EncryptionState
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
import Control.Monad(void, when, unless, forever, join, forM_)
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
import Data.Foldable hiding (all,forM_)
#endif
import Data.IntSet(IntSet)
import qualified Data.IntSet as IntSet
import Data.Maybe
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Tuple
import Data.Word
import Data.X509
import Hexdump
import Network.TLS(HasBackend)
#if !MIN_VERSION_base(4,8,0)
import Prelude hiding (mapM_)
#endif
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.HybridCrypto
import Tor.Link
import Tor.Link.DH
import Tor.NetworkStack
import Tor.Options
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Credentials
import Tor.State.Routers

-- -----------------------------------------------------------------------------

-- |A circuit that originates with this node
data OriginatedCircuit = OriginatedCircuit {
         ocLink            :: TorLink
       , ocLog             :: String -> IO ()
       , ocId              :: Word32
       , ocRNG             :: MVar TorRNG
       , ocOptions         :: TorOptions
       , ocState           :: MVar (Either DestroyReason [ThreadId])
       , ocTakenStreamIds  :: MVar IntSet
       , ocExtendWaiter    :: MVar RelayCell
       , ocResolveWaiters  :: MVar (Map Word16 (MVar [(TorAddress, Word32)]))
       , ocSockets         :: MVar (Map Word16 TorSocket)
       , ocConnWaiters     :: MVar (Map Word16 (MVar (Either String TorSocket)))
       , ocForeCryptoData  :: MVar [CryptoData]
       , ocBackCryptoData  :: MVar [CryptoData]
       }


-- |Create a new one-hop circuit across the given link. The router description
-- given must be the router description for the given link, or the handshake
-- will fail. The Word32 argument is the circuit id to use. The result is the
-- new, one-hop circuit or a thrown exception. If you care about anonymity, you
-- should extend this circuit a few times before trying to make any
-- connections.
createCircuit :: MVar TorRNG -> TorOptions ->
                 TorLink -> RouterDesc -> Word32 ->
                 IO OriginatedCircuit
createCircuit ocRNG ocOptions ocLink router1 ocId =
  case routerNTorOnionKey router1 of
    Nothing ->
      do (x,cbstr) <- modifyMVar' ocRNG (startTAPHandshake router1)
         linkWrite ocLink (Create ocId cbstr)
         Created cid bstr <- linkRead ocLink ocId
         unless ((ocId == cid) && (S.length bstr == (128    + 20))) $
           fail "Unacceptable response to CREATE message."
         finishCreateCircuit (completeTAPHandshake x bstr)
    Just _ ->
      do Just (pair, cbody) <- modifyMVar' ocRNG (startNTorHandshake router1)
         linkWrite ocLink (Create2 ocId NTor cbody)
         Created2 cid bstr <- linkRead ocLink ocId
         unless ((ocId == cid) && (S.length bstr == (32 + 32))) $
           fail "Unacceptable response to CREATE2 message."
         finishCreateCircuit (completeNTorHandshake router1 pair bstr)
 where
  ocLog = torLog ocOptions
  finishCreateCircuit (Left err) = failLog ("Create handshake failed: " ++ err)
  finishCreateCircuit (Right (fencstate, bencstate)) =
    do ocForeCryptoData <- newMVar [fencstate]
       ocBackCryptoData <- newMVar [bencstate]
       ocState          <- newEmptyMVar
       ocTakenStreamIds <- newMVar IntSet.empty
       ocExtendWaiter   <- newEmptyMVar
       ocSockets        <- newMVar Map.empty
       ocResolveWaiters <- newMVar Map.empty
       ocConnWaiters    <- newMVar Map.empty
       let circ = OriginatedCircuit { .. }
       handler <- forkIO (runBackward circ)
       putMVar ocState (Right [handler])
       ocLog ("Created circuit " ++ show ocId)
       return circ
  --
  failLog str = ocLog str >> throwIO (userError str)
  runBackward circ =
    forever $ do next <- linkRead ocLink ocId
                 processBackwardInput circ next

-- |Extend the extant circuit to the given router. This is purely
-- side-effecting, although it may thrw an error if an error occurs during the
-- extension process.
extendCircuit :: OriginatedCircuit -> RouterDesc -> IO ()
extendCircuit circ nxt =
  do state <- readMVar (ocState circ)
     when (isLeft state) $
       throwIO (userError ("Attempted to extend a closed circuit."))
     case Nothing of -- routerNTorOnionKey nxt of
       Nothing ->
         do (x,b) <- modifyMVar' (ocRNG circ) (startTAPHandshake nxt)
            writeCellOnCircuit circ RelayExtend {
                relayStreamId      = 0
              , relayExtendAddress = routerIPv4Address nxt
              , relayExtendPort    = routerORPort nxt
              , relayExtendSkin    = b
              , relayExtendIdent   = keyHash' sha1 (routerSigningKey nxt)
              }
            res@RelayExtended{} <- takeMVar (ocExtendWaiter circ)
            finishExtend (completeTAPHandshake x (relayExtendedData res))
       Just _ ->
         do Just (p,b) <- modifyMVar' (ocRNG circ) (startNTorHandshake nxt)
            let ip4 = routerIPv4Address nxt
            writeCellOnCircuit circ RelayExtend2 {
                relayStreamId      = 0
              , relayExtendTarget  = [ExtendIP4 ip4 (routerORPort nxt)]
              , relayExtendType    = NTor
              , relayExtendData    = b
              }
            res@RelayExtended2{} <- takeMVar (ocExtendWaiter circ)
            finishExtend (completeNTorHandshake nxt p (relayExtendedData res))
 where
  finishExtend (Left err) =
    throwIO (userError ("Failed extension handshake on circuit " ++
                        show (ocId circ) ++ ": " ++ err))
  finishExtend (Right (fencstate, bencstate)) =
    do modifyMVar_ (ocForeCryptoData circ) $ \ rest ->
         return (rest ++ [fencstate])
       modifyMVar_ (ocBackCryptoData circ) $ \ rest ->
         return (rest ++ [bencstate])

-- |Destroy a circuit, and all the streams and computations running through it.
destroyCircuit :: OriginatedCircuit -> DestroyReason -> IO ()
destroyCircuit circ rsn =
  do ts <- modifyMVar (ocState circ) $ \ state ->
            case state of
              Left _ -> return (state, [])
              Right threads ->
                do mapM_ killSockets     =<< readMVar (ocSockets circ)
                   mapM_ killConnWaiters =<< readMVar (ocConnWaiters circ)
                   mapM_ killResWaiters  =<< readMVar (ocResolveWaiters circ)
                   -- FIXME: Send a message out, kill the crypto after
                   _ <- takeMVar (ocForeCryptoData circ)
                   _ <- takeMVar (ocBackCryptoData circ)
                   ocLog circ ("Destroy circuit " ++ show (ocId circ) ++
                               ": " ++ show rsn)
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

-- |Write a cell on the circuit we just created, pushing it through the network.
writeCellOnCircuit :: OriginatedCircuit -> RelayCell -> IO ()
writeCellOnCircuit circ relay =
  do keysnhashes <- takeMVar (ocForeCryptoData circ)
     let (cell, keysnhashes') = synthesizeRelay keysnhashes
     linkWrite (ocLink circ) (pickBuilder relay (ocId circ) cell)
     putMVar (ocForeCryptoData circ) keysnhashes'
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

-- ----------------------------------------------------------------------------

-- |A handle for a circuit that orginated elsewhere, and is either passing
-- through or exiting at this node.
data TransverseCircuit s = TransverseCircuit {
         tcLink            :: TorLink
       , tcNextHop         :: MVar TorLink
       , tcLog             :: String -> IO ()
       , tcId              :: Word32
       , tcRNG             :: MVar TorRNG
       , tcOptions         :: TorOptions
       , tcCredentials     :: Credentials
       , tcRouterDB        :: RouterDB
       , tcConnections     :: MVar (Map Word16 s)
       , tcThreads         :: MVar [ThreadId]
       , tcForeCryptoData  :: MVar CryptoData
       , tcBackCryptoData  :: MVar CryptoData
       }


-- |Accept a circuit from someone who just connected to us.
acceptCircuit :: HasBackend s =>
                 TorNetworkStack ls s -> TorOptions ->
                 RouterDesc -> Credentials -> RouterDB ->
                 TorLink -> MVar TorRNG ->
                 IO (Maybe (TransverseCircuit s))
acceptCircuit ns tcOptions me tcCredentials tcRouterDB tcLink tcRNG =
  do msg <- linkRead tcLink 0
     (_, PrivKeyRSA priv) <- getOnionKey tcCredentials
     (_, skey) <- getNTorOnionKey tcCredentials
     case msg of
       Create tcId bstr ->
         do (created, fes, bes) <- modifyMVar' tcRNG
                                    (advanceTAPHandshake priv tcId bstr)
            tcForeCryptoData <- newMVar fes
            tcBackCryptoData <- newMVar bes
            tcConnections    <- newMVar Map.empty
            tcThreads        <- newEmptyMVar
            tcNextHop        <- newEmptyMVar
            let circ          = TransverseCircuit { .. }
            thread           <- forkIO (runForward circ)
            putMVar tcThreads [thread]
            linkWrite tcLink created
            tcLog ("Created transverse circuit " ++ show tcId)
            return (Just circ)
       Create2 tcId TAP bstr ->
         do (created, fes, bes) <- modifyMVar' tcRNG
                                    (advanceTAPHandshake priv tcId bstr)
            tcForeCryptoData <- newMVar fes
            tcBackCryptoData <- newMVar bes
            tcConnections    <- newMVar Map.empty
            tcThreads        <- newEmptyMVar
            tcNextHop        <- newEmptyMVar
            let circ          = TransverseCircuit { .. }
            thread           <- forkIO (runForward circ)
            putMVar tcThreads [thread]
            linkWrite tcLink created
            tcLog ("Created transverse circuit " ++ show tcId)
            return (Just circ)
       Create2 tcId NTor bstr ->
         -- FIXME: Really should gate this on "UseNTorHandshake" being in the
         -- consensus parameters.
         do res <- modifyMVar' tcRNG (advanceNTorHandshake me skey tcId bstr)
            case res of
              Left err ->
                do tcLog ("Error creating transverse circuit: " ++ err)
                   linkWrite tcLink (Destroy tcId TorProtocolViolation)
                   return Nothing
              Right (response, fes, bes) ->
                do tcForeCryptoData <- newMVar fes
                   tcBackCryptoData <- newMVar bes
                   tcConnections    <- newMVar Map.empty
                   tcThreads        <- newEmptyMVar
                   tcNextHop        <- newEmptyMVar
                   let circ          = TransverseCircuit { .. }
                   thread           <- forkIO (runForward circ)
                   putMVar tcThreads [thread]
                   linkWrite tcLink response
                   tcLog ("Create transverse circuit (ntor) " ++ show tcId)
                   return (Just circ)
       Create2 tcId hstype _ ->
         do tcLog ("Unfamiliar CREATE2 handshake type: " ++ show hstype)
            linkWrite tcLink (Destroy tcId TorProtocolViolation)
            return Nothing
       CreateFast tcId _ ->
         -- FIXME: Really should look up "usecreatefast" in the consensus
         -- parameters.
         do tcLog ("Rejecting CREATE_FAST attempt.")
            linkWrite tcLink (Destroy tcId TorProtocolViolation)
            return Nothing
       _ ->
         do tcLog ("Unexpected message waiting for CREATE: " ++ show msg)
            linkWrite tcLink (Destroy 0 TorProtocolViolation)
            return Nothing
 where
  tcLog = torLog tcOptions
  runForward circ =
    forever $ do next <- linkRead tcLink (tcId circ)
                 processForwardInput ns circ next

-- |Destroy a circuit that is transiting us.
destroyTransverse :: TorNetworkStack ls s ->
                     TransverseCircuit s -> DestroyReason ->
                     IO ()
destroyTransverse ns circ rsn =
  do tcLog circ ("Destroy transverse circuit: " ++ show rsn)
     mlink <- tryTakeMVar (tcNextHop circ)
     case mlink of
       Nothing   -> return ()
       Just link -> linkClose link
     thrs <- takeMVar (tcThreads circ)
     forM_ thrs killThread
     conns <- takeMVar (tcConnections circ)
     forM_ (Map.elems conns) $ \ s -> close ns s

-- ----------------------------------------------------------------------------

processBackwardInput :: OriginatedCircuit -> TorCell -> IO ()
processBackwardInput circ cell =
  handle logException $
    case cell of
      Relay      _ body -> processBackwardRelay circ body
      RelayEarly _ body -> processBackwardRelay circ body
      Destroy    _ rsn  -> destroyCircuit circ rsn
      _                 -> ocLog circ ("Spurious message along circuit.")
 where
  logException e =
    ocLog circ ("Caught exception processing backwards input: "
                ++ show (e :: SomeException))

processBackwardRelay :: OriginatedCircuit -> ByteString -> IO ()
processBackwardRelay circ body =
  do clearBody <- modifyMVar' (ocBackCryptoData circ) (decryptUntilClean body)
     case clearBody of
       Nothing -> ocLog circ "Dropped upstream packet on originated circuit."
       Just x  -> processLocalBackwardsRelay circ x
 where
  decryptUntilClean :: ByteString -> [CryptoData] ->
                       ([CryptoData], Maybe RelayCell)
  decryptUntilClean _    []                    = ([], Nothing)
  decryptUntilClean bstr ((encstate, h1):rest) =
    let (bstr', encstate') = decryptData encstate bstr
    in case runGetOrFail (parseRelayCell h1) (L.fromStrict bstr') of
         Left _ ->
           let (rest', res) = decryptUntilClean bstr' rest
           in ((encstate', h1) : rest', res)
         Right (_, _, (x, h1')) ->
           (((encstate', h1') : rest), Just x)

processLocalBackwardsRelay :: OriginatedCircuit -> RelayCell -> IO ()
processLocalBackwardsRelay circ x =
  case x of
    RelayData{ relayStreamId = strmId, relayData = bstr } ->
      withMVar (ocSockets circ) $ \ smap ->
        case Map.lookup strmId smap of
          Nothing ->
            ocLog circ ("Dropping traffic to unknown stream " ++ show strmId)
          Just sock ->
            do state <- readMVar (tsState sock)
               unless (isJust state) $ writeChan (tsInChan sock) (Right bstr)

    RelayEnd{ relayStreamId = strmId, relayEndReason = rsn } ->
       modifyMVar_ (ocSockets circ) $ \ smap ->
         case Map.lookup strmId smap of
           Nothing ->
             return smap
           Just sock ->
             do modifyMVar_ (tsState sock) (const (return (Just rsn)))
                writeChan (tsInChan sock) (Left rsn)
                return (Map.delete strmId smap)

    RelayConnected{ relayStreamId = tsStreamId } ->
      modifyMVar_ (ocConnWaiters circ) $ \ cwaits ->
        case Map.lookup tsStreamId cwaits of
          Nothing ->
            do ocLog circ ("CONNECTED without waiter?")
               return cwaits
          Just wait ->
            do let tsCircuit = circ
               tsState      <- newMVar Nothing
               tsInChan     <- newChan
               tsLeftover   <- newMVar S.empty
               tsReadWindow <- newMVar 500 -- See spec, 7.4, stream flow
               let sock = TorSocket { .. }
               modifyMVar_ (ocSockets circ) $ \ socks ->
                 return (Map.insert tsStreamId sock socks)
               _ <- tryPutMVar wait (Right sock)
               return (Map.delete tsStreamId cwaits)

    RelaySendMe {} ->
      do ocLog circ "SENDME"
         return ()

    RelayExtended {} ->
      void $ tryPutMVar (ocExtendWaiter circ) x

    RelayTruncated {} ->
      do ocLog circ ("TRUNCATED: " ++ show (relayTruncatedRsn x))
         return () -- FIXME

    RelayDrop {} ->
      return ()

    RelayResolved { relayStreamId = strmId } ->
      modifyMVar_ (ocResolveWaiters circ) $ \ resolveds ->
        case Map.lookup strmId resolveds of
          Nothing ->
            do ocLog circ ("Resolved unknown request.")
               return resolveds
          Just wait ->
            do _ <- tryPutMVar wait (relayResolvedAddrs x)
               return (Map.delete strmId resolveds)

    RelayExtended2 {} ->
      void $ tryPutMVar (ocExtendWaiter circ) x

    _ ->
      ocLog circ ("Unexpected relay cell on backward link.")

-- ----------------------------------------------------------------------------

processForwardInput :: HasBackend s =>
                       TorNetworkStack ls s -> TransverseCircuit s -> TorCell ->
                       IO ()
processForwardInput ns circ cell =
  handle logException $
    case cell of
      Relay      circId body -> processForwardRelay ns circ circId body
      RelayEarly circId body -> processForwardRelay ns circ circId body
      Destroy    _      rsn  -> destroyTransverse   ns circ rsn
      _                      ->
        tcLog circ ("Spurious message along circuit.")
 where
  logException e =
    tcLog circ ("Caught exception processing backwards input: "
                  ++ show (e :: SomeException))

processForwardRelay :: HasBackend s =>
                       TorNetworkStack ls s -> TransverseCircuit s ->
                       Word32 -> ByteString ->
                       IO ()
processForwardRelay ns circ circId body =
  do clearBody <- modifyMVar' (tcForeCryptoData circ) (decryptBody body)
     case clearBody of
       Left  body' ->
         do mlink <- tryReadMVar (tcNextHop circ)
            case mlink of
              Nothing   -> return ()
              Just link -> linkWrite link (Relay circId body')
       Right x     -> processLocalForwardRelay ns circ x
 where
  decryptBody bstr (encstate, h1) =
    let (bstr', encstate') = decryptData encstate bstr
    in case runGetOrFail (parseRelayCell h1) (L.fromStrict bstr') of
         Left _                 -> ((encstate', h1),  Left bstr')
         Right (_, _, (x, h1')) -> ((encstate', h1'), Right x)

processLocalForwardRelay :: HasBackend s =>
                            TorNetworkStack ls s ->
                            TransverseCircuit s -> RelayCell ->
                            IO ()
processLocalForwardRelay ns circ x =
  case x of
    RelayBegin{} | not (isExitNode circ) ->
      circRelayUpstream circ (RelayEnd (relayStreamId x) ReasonTorProtocol)

    RelayBegin{ relayStreamId = strmId } ->
      -- FIXME: Figure out how to get TTLs from our network stacks.
      void $ forkIO $
        do eaddr <- getAddress' ns (relayBeginAddress x)
           case eaddr of
             [] ->
               circRelayUpstream circ (RelayEnd strmId ReasonResolveFailed)
             (f:_) | matchesExitCriteria f (relayBeginPort x) circ ->
               do ms <- connect' ns f (relayBeginPort x)
                  case ms of
                    Nothing ->
                      circRelayUpstream circ
                        (RelayEnd strmId ReasonConnectionRefused)
                    Just sock ->
                      do modifyMVar_' (tcConnections circ) (Map.insert strmId sock)
                         readThr <- forkIO $ transferData sock
                         modifyMVar_' (tcThreads circ) (readThr :)
                         circRelayUpstream circ (RelayConnected strmId f 600)
             (f:_) ->
               circRelayUpstream circ (RelayEnd strmId (ReasonExitPolicy f 600))
     where
      transferData sock =
        do bstr <- recv ns sock 1024
           if S.null bstr
              then do close ns sock
                      circRelayUpstream circ (RelayEnd strmId ReasonDone)
              else do circRelayUpstream circ (RelayData strmId bstr)
                      transferData sock

    RelayData{ relayStreamId = strmId } ->
      void $ forkIO $
        do msock <- withMVar' (tcConnections circ) (Map.lookup strmId)
           case msock of
             Nothing -> tcLog circ "Ignoring write to unknown stream."
             Just s  -> write ns s (L.fromStrict (relayData x))

    RelayEnd{ relayStreamId = strmId } ->
      do msock <- withMVar' (tcConnections circ) (Map.lookup strmId)
         case msock of
           Nothing -> tcLog circ "Ignoring end to unknown stream."
           Just s  -> close ns s

    RelaySendMe{} ->
      return () -- FIXME

    RelayExtend{ relayStreamId = strmId } ->
      void $ forkIO $ handle abortExtend tryExtend
     where
      abortExtend :: SomeException -> IO ()
      abortExtend _ = circRelayUpstream circ (RelayEnd strmId ReasonTorProtocol)
      --
      tryExtend =
        do let target = [ExtendIP4 (relayExtendAddress x) (relayExtendPort x),
                         ExtendDigest (relayExtendIdent x)]
           tcLog circ ("Going to try to extending a circuit to " ++ show target)
           Just desc <- findRouter (tcRouterDB circ) target
           -- FIXME: Run this through the link manager, instead.
           link <- initLink ns (tcCredentials circ) (tcRNG circ) (tcLog circ) desc
           linkWrite link (Create (tcId circ) (relayExtendSkin x))
           Created cid bstr <- linkRead link (tcId circ)
           unless ((tcId circ == cid) && (S.length bstr == (128 + 20))) $
             fail "Unacceptable response to extend CREATE message."
           good <- tryPutMVar (tcNextHop circ) link
           if good
              then do circRelayUpstream circ (RelayExtended strmId bstr)
                      tcLog circ "Circuit extension succeeded."
                      forever $ do next <- linkRead link (tcId circ)
                                   processBackwardTransverse circ next
              else do tcLog circ "Duplicate extension. Failing."
                      linkClose link
                      fail "Duplicate extension."

    RelayTruncate{} ->
      void $ forkIO $
        do mlink <- tryReadMVar (tcNextHop circ)
           case mlink of
             Nothing   -> return ()
             Just link -> linkWrite link (Destroy (tcId circ) NoReason)
           circRelayUpstream circ (RelayTruncated 0 NoReason)

    RelayDrop{} ->
      return ()

    RelayResolve{} | not (isExitNode circ) ->
      circRelayUpstream circ (RelayEnd (relayStreamId x) ReasonTorProtocol)

    RelayResolve{ relayStreamId = strmId, relayResolveName = name } ->
      void $ forkIO $
        do resolve <- getAddress ns name
           let results = map (\ a -> (a, 600)) resolve -- FIXME: TTLs!
           circRelayUpstream circ (RelayResolved strmId results)

    RelayBeginDir{ relayStreamId = strmId } ->
      circRelayUpstream circ (RelayEnd strmId ReasonNotDirectory)

    RelayExtend2{ relayStreamId = strmId } ->
      void $ forkIO $ handle abortExtend tryExtend
     where
      abortExtend :: SomeException -> IO ()
      abortExtend _ = circRelayUpstream circ (RelayEnd strmId ReasonTorProtocol)
      --
      tryExtend = -- FIXME: This is probably worth abstracting
        do let target = relayExtendTarget x
           tcLog circ ("Going to try to extending a circuit to " ++ show target)
           Just desc <- findRouter (tcRouterDB circ) target
           -- FIXME: Run this through the link manager, instead.
           link <- initLink ns (tcCredentials circ) (tcRNG circ) (tcLog circ) desc
           linkWrite link (Create2 (tcId circ) (relayExtendType x) (relayExtendSkin x))
           Created2 cid bstr <- linkRead link (tcId circ)
           unless ((tcId circ == cid) && (S.length bstr == (32 + 32))) $
             fail "Unacceptable response to extend CREATE2 message."
           good <- tryPutMVar (tcNextHop circ) link
           if good
              then do circRelayUpstream circ (RelayExtended2 strmId bstr)
                      tcLog circ "Circuit extension succeeded."
                      forever $ do next <- linkRead link (tcId circ)
                                   processBackwardTransverse circ next
              else do tcLog circ "Duplicate extension. Failing."
                      linkClose link
                      fail "Duplicate extension."

    _ ->
      tcLog circ ("Unexpected relay cell on backward link.")

processBackwardTransverse :: TransverseCircuit s -> TorCell -> IO ()
processBackwardTransverse circ cell =
  case cell of
    Relay      _ body -> process body
    RelayEarly _ body -> process body
    _ -> tcLog circ ("Got weird backwards transverse cell: " ++ show cell)
 where
   process body =
     do body' <- modifyMVar' (tcBackCryptoData circ) (processBody body)
        linkWrite (tcLink circ) (Relay (tcId circ) body')
   processBody body (estate, hash) =
     let (body', estate') = encryptData estate body
     in ((estate', hash), body')

isExitNode :: TransverseCircuit s -> Bool
isExitNode = isJust . torExitOptions . tcOptions

getAddress' :: TorNetworkStack ns s -> TorAddress -> IO [TorAddress]
getAddress' ns addr =
  case addr of
    Hostname str -> getAddress ns str
    IP4      _   -> return [addr]
    IP6      _   -> return [addr]
    _            -> return []

connect' :: TorNetworkStack ns s -> TorAddress -> Word16 -> IO (Maybe s)
connect' ns (IP4 a) p = connect ns a p
connect' ns (IP6 a) p = connect ns a p
connect' _  _       _ = return Nothing

matchesExitCriteria :: TorAddress -> Word16 -> TransverseCircuit s -> Bool
matchesExitCriteria addr port circ =
  case torExitOptions (tcOptions circ) of
    Nothing   -> False
    Just opts -> allowsExit (torExitRules opts) addr port

circRelayUpstream :: TransverseCircuit s -> RelayCell -> IO ()
circRelayUpstream circ relay =
  do cell <- modifyMVar' (tcBackCryptoData circ) synthesizeRelay
     linkWrite (tcLink circ) (Relay (tcId circ) cell)
 where
  synthesizeRelay (estate, hash) =
    let (bstr, hash')      = renderRelayCell hash relay
        (encbstr, estate') = encryptData estate bstr
    in ((estate', hash'), encbstr)

-- ----------------------------------------------------------------------------

-- |Resolve the given hostname, anonymously. The result is a list of addresses
-- associated with that hostname, and the TTL for those values.
resolveName :: OriginatedCircuit -> String -> IO [(TorAddress, Word32)]
resolveName circ str =
  do strmId <- getNextStreamId circ
     resMV  <- newEmptyMVar
     modifyMVar_ (ocResolveWaiters circ) $ \ m ->
       return (Map.insert strmId resMV m)
     writeCellOnCircuit circ (RelayResolve strmId str)
     takeMVar resMV

-- ----------------------------------------------------------------------------

-- |A socket for communicating with a server, anonymously, via Tor.
data TorSocket = TorSocket {
       tsCircuit    :: OriginatedCircuit
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
connectToHost :: OriginatedCircuit -> TorAddress -> Word16 -> IO TorSocket
connectToHost tc a p = connectToHost' tc a p True True False

-- |Connect to the given address and port through the given circuit. The result
-- is a connection that can be used to read, write, and close the connection.
-- The booleans determine if an IPv4 connection is OK, an IPv6 connection is OK,
-- and whether IPv6 is preferred, respectively.
connectToHost' :: OriginatedCircuit ->
                  TorAddress -> Word16 ->
                  Bool -> Bool -> Bool ->
                  IO TorSocket
connectToHost' circ addr port ip4ok ip6ok ip6pref =
  do strmId <- getNextStreamId circ
     resMV  <- newEmptyMVar
     modifyMVar_ (ocConnWaiters circ) $ \ m ->
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

-- |Close a Tor socket. This will notify the other end of the connection that
-- you are done, so you should be sure you really don't need to do any more
-- reading before calling this. At this point, this implementation does not
-- support a half-closed option.
torClose :: TorSocket -> RelayEndReason -> IO ()
torClose sock reason =
  do let strmId = tsStreamId sock
     modifyMVar_ (tsState sock) (const (return (Just reason)))
     modifyMVar_' (ocSockets (tsCircuit sock)) (Map.delete strmId)
     writeCellOnCircuit (tsCircuit sock) (RelayEnd strmId reason)

-- ----------------------------------------------------------------------------

-- |The current state of an encryptor.
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

getNextStreamId :: OriginatedCircuit -> IO Word16
getNextStreamId circ =
  do nextId <- modifyMVar' (ocRNG circ) randWord16
     let nextId' = fromIntegral nextId
     good   <- modifyMVar (ocTakenStreamIds circ) $ \ set ->
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

-- |Perform the first step in a TAP handshake, generating a private value and
-- the public cell body to send to the other side.
startTAPHandshake :: RouterDesc -> TorRNG ->
                     (TorRNG, (PrivateNumber, ByteString))
startTAPHandshake rtr g = (g'', (x, egx))
 where
  (x, g')         = withDRG g (generatePrivate oakley2)
  PublicNumber gx = calculatePublic oakley2 x
  gxBS            = i2ospOf_ 128 gx
  nodePub         = routerOnionKey rtr
  (egx, g'')      = withDRG g' (hybridEncrypt True nodePub gxBS)

-- |Given our information and the public value provided by the other side,
-- compute both the shared secret and our public value to send back to the
-- originator.
advanceTAPHandshake :: PrivateKey -> Word32 -> ByteString -> TorRNG ->
                       (TorRNG, (TorCell, CryptoData, CryptoData))
advanceTAPHandshake privkey circId egx g = (g'', (created, f, b))
 where
  (y, g')         = withDRG g (generatePrivate oakley2)
  PublicNumber gy = calculatePublic oakley2 y
  gyBS            = i2ospOf_ 128 gy
  (gxBS, g'')     = withDRG g' (hybridDecrypt privkey egx)
  gx              = PublicNumber (os2ip gxBS)
  (kh, f, b)      = computeTAPValues y gx
  created         = Created circId (gyBS `S.append` kh)

-- |Given the private number generated before and the server's response,
-- generate the shared secret and the appropriate crypto data.
completeTAPHandshake :: PrivateNumber -> ByteString ->
                        Either String (CryptoData, CryptoData)
completeTAPHandshake x rbstr
  | kh == kh' = Right (f, b)
  | otherwise = Left "Key agreement failure."
 where
  (gyBS, kh)   = S.splitAt 128 rbstr
  gy           = PublicNumber (os2ip gyBS)
  (kh', f, b)  = computeTAPValues x gy

computeTAPValues :: PrivateNumber -> PublicNumber ->
                    (ByteString, CryptoData, CryptoData)
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

-- |A shorthand for the pair of encryption and hashing state used by Tor. Note,
-- because it's easy to forget, that the encryption state is updated on every
-- cell that passes through the system, but the hashing state is only updated on
-- cells that are destined for us.
type CryptoData = (EncryptionState, Context SHA1)

-- |Start an NTor handshake by generating a local Curve25519 pair and a public
-- value to send to the server.
startNTorHandshake :: RouterDesc -> TorRNG ->
                     (TorRNG, Maybe (Curve25519Pair, ByteString))
startNTorHandshake router g0 =
  case routerNTorOnionKey router of
    Nothing ->
      (g0, Nothing)
    Just key ->
      let (pair@(bigX, _), g1) = withDRG g0 generate25519
          nodeid = routerFingerprint router
          client_pk = convert bigX
          bstr = S.concat [nodeid, convert key, client_pk]
      in (g1, Just (pair, bstr))

-- |As a server, accept the client's public value, generate the shared
-- encryption state from that value, and generate a response to the client they
-- can use to generate the same values.
advanceNTorHandshake :: RouterDesc -> Curve.SecretKey -> Word32 ->
                        ByteString -> TorRNG ->
                        (TorRNG,
                         Either String (TorCell, CryptoData, CryptoData))
advanceNTorHandshake me littleB circId bstr0 g0
  | Nothing <- routerNTorOnionKey me =
      (g0, Left "Called advance, but I don't support NTor handshakes.")
  | (nodeid /= routerFingerprint me) || (Just bigB /= routerNTorOnionKey me) =
      (g0, Left "Called advance, but their fingerprint doesn't match me.")
  | Left err <- toEither (publicKey keyid) =
      (g0, Left ("Couldn't decode bigX in advance: " ++ err))
  | otherwise = (g1, Right (msg,fenc,benc))
 where
  (nodeid, bstr1)       = S.splitAt 20 bstr0
  (keyid,  xpub)        = S.splitAt 32 bstr1
  Right bigB            = toEither (publicKey keyid)
  Right bigX            = toEither (publicKey xpub)
  ((bigY, littleY), g1) = withDRG g0 generate25519
  secret_input          = S.concat [curveExp bigX littleY,
                                    curveExp bigX littleB,
                                    nodeid, convert bigB, convert bigX,
                                    convert bigY, protoid]
  key_seed              = hmacSha256 t_key secret_input
  verify                = hmacSha256 t_verify secret_input
  auth_input            = S.concat [verify, nodeid, convert bigB, convert bigY,
                                    convert bigX, protoid, S8.pack "Server"]
  server_pk             = convert bigY
  auth                  = hmacSha256 t_mac auth_input
  --
  msg                   = Created2 circId outdata
  outdata               = S.concat [server_pk, auth]
  (fenc, benc)          = computeNTorValues key_seed

-- |Complete the NTor handhsake using the server's public value.
completeNTorHandshake :: RouterDesc -> Curve25519Pair -> ByteString ->
                         Either String (CryptoData, CryptoData)
completeNTorHandshake router (bigX, littleX) bstr
  | Nothing <- routerNTorOnionKey router =
      Left "Internal error complete/ntor"
  | Left err <- toEither (publicKey public_pk) =
      Left ("Couldn't decode bigY: "++err)
  | Left err <- toEither (publicKey server_ntorid) =
      Left ("Couldn't decode bigB: "++err)
  | auth /= auth' =
      Left "Authorization failure"
  | otherwise =
      Right res
 where
  nodeid             = routerFingerprint router
  (public_pk, auth)  = S.splitAt 32 bstr
  Just server_ntorid = routerNTorOnionKey router
  Right bigY         = toEither (publicKey public_pk)
  Right bigB         = toEither (publicKey server_ntorid)
  secret_input       = S.concat [curveExp bigY littleX, curveExp bigB littleX,
                                 nodeid, convert bigB, convert bigX, convert bigY,
                                 protoid]
  key_seed           = hmacSha256 t_key secret_input 
  verify             = hmacSha256 t_verify secret_input
  auth_input         = S.concat [verify, nodeid, convert bigB, convert bigY,
                                 convert bigX, protoid, S8.pack "Server"]
  auth'              = hmacSha256 t_mac auth_input
  res                = computeNTorValues key_seed

curveExp :: Curve.PublicKey -> Curve.SecretKey -> ByteString
curveExp a b = convert (dh a b)

-- |A handy shorthand for a public and private Curve25519 pair.
type Curve25519Pair = (Curve.PublicKey, Curve.SecretKey)

-- |Generate a new Curve25519 key pair.
generate25519 :: MonadRandom m => m Curve25519Pair
generate25519 =
  do bytes <- getRandomBytes 32
     case toEither (secretKey (bytes :: ByteString)) of
       Left err ->
         fail ("Couldn't convert to a secret key: " ++ show err)
       Right privKey ->
         do let pubKey = toPublic privKey
            return (pubKey, privKey)

computeNTorValues :: ByteString -> (CryptoData, CryptoData)
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
   | i == 1    = hmacSha256 kseed (m_expand `S.snoc` 1)
   | otherwise = hmacSha256 kseed (S.concat [kn (i-1),m_expand,S.singleton i])

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

-- -----------------------------------------------------------------------------

withMVar' :: MVar a -> (a -> b) -> IO b
withMVar' mv f = withMVar mv (return . f)

modifyMVar' :: MVar a -> (a -> (a, b)) -> IO b
modifyMVar' mv f = modifyMVar mv (return . f)

modifyMVar_' :: MVar a -> (a -> a) -> IO ()
modifyMVar_' mv f = modifyMVar_ mv (return . f)

#if MIN_VERSION_cryptonite(0,9,0)
toEither :: CryptoFailable a -> Either String a
toEither (CryptoPassed x) = Right x
toEither (CryptoFailed e) = Left (show e)
#else
toEither :: Either String a -> Either String a
toEither = id
#endif
