module Test.Network.Socket(
         ListenerTable
       , newListenerTable
         --
       , TestNetworkStack
       , TestSocket
       , buildTestNetworkStack
         --
       , testSockets
       )
 where

import           Control.Concurrent(forkIO, threadDelay)
import           Control.Concurrent.Chan(Chan, newChan, readChan, writeChan)
import           Control.Concurrent.MVar(MVar, newMVar)
import           Control.Concurrent.MVar(newEmptyMVar, readMVar, modifyMVar_)
import           Control.Concurrent.MVar(putMVar, takeMVar)
import           Control.Monad(unless)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.IORef(IORef, newIORef, readIORef, atomicModifyIORef')
import           Data.Map.Strict(Map)
import qualified Data.Map.Strict as M
import           Data.Word(Word16)
import           Network.TLS(HasBackend(..), Backend(..))
import           System.Timeout(timeout)
import           Test.Framework(Test, testGroup)
import           Test.Framework.Providers.HUnit(testCase)
import           Test.Framework.Providers.QuickCheck2(testProperty)
import           Test.HUnit.Base(Assertion, assertEqual)
import           Test.Network.ByteChan(ByteChan, newByteChan, testByteChan)
import           Test.Network.ByteChan(readByteChan, writeByteChan)
import           Test.Network.ByteChan(isEmptyByteChan)
import           Test.QuickCheck(Property)
import           Test.QuickCheck.Monadic(monadicIO, run, pre, assert)
import           Test.Standard()
import           Tor.DataFormat.TorAddress(TorAddress(..))
import           Tor.NetworkStack(TorNetworkStack(..))

type TestNetworkStack = TorNetworkStack TestListenSocket TestSocket

buildTestNetworkStack :: ListenerTable ->
                         Map String [TorAddress] ->
                         TorAddress ->
                         TestNetworkStack
buildTestNetworkStack ltableIO dnsMap myAddress = TorNetworkStack {
    connect    = testConnect       ltableIO myAddress
  , getAddress = \ name -> return (M.findWithDefault [] name dnsMap)
  , listen     = testLSocketListen ltableIO myAddress
  , accept     = testLSocketAccept
  , lclose     = testLSocketClose  ltableIO
  , recv       = testSocketRecv
  , write      = testSocketSend
  , flush      = testSocketFlush
  , close      = testSocketClose
  }

-- -----------------------------------------------------------------------------

type ListenerTable = IORef (Map (TorAddress, Word16)
                                (Chan (TorAddress, MVar TestSocket)))

newListenerTable :: IO ListenerTable
newListenerTable = newIORef M.empty

-- -----------------------------------------------------------------------------

testConnect :: ListenerTable -> TorAddress ->
               String -> Word16 ->
               IO (Maybe TestSocket)
testConnect ltableIO myAddr addr port = loop (0 :: Int)
 where
  loop x =
    do ltable <- readIORef ltableIO
       case M.lookup (IP4 addr, port) ltable of
         Nothing | x >= 10 ->
           return Nothing
         Nothing ->
           do threadDelay 100000
              loop (x + 1)
         Just ch ->
           do waitMV <- newEmptyMVar
              writeChan ch (myAddr, waitMV)
              Just `fmap` takeMVar waitMV

-- -----------------------------------------------------------------------------

data TestListenSocket = TestListenSocket {
       tlsMyKey       :: (TorAddress, Word16)
     , tlsRequestChan :: Chan (TorAddress, MVar TestSocket)
     }

testLSocketListen :: ListenerTable -> TorAddress ->
                     Word16 ->
                     IO TestListenSocket
testLSocketListen ltableIO addr port =
  do chan <- newChan
     atomicModifyIORef' ltableIO $ \ ltable ->
       let key = (addr, port)
           ltable' = M.insert key chan ltable
           res     = TestListenSocket key chan
       in (ltable', res)

testLSocketAccept :: TestListenSocket -> IO (TestSocket, TorAddress)
testLSocketAccept tls =
  do (addr, mv) <- readChan (tlsRequestChan tls)
     conToAcc   <- newByteChan
     accToCon   <- newByteChan
     mySocket   <- TS `fmap` newMVar (OpenSocket conToAcc accToCon)
     thSocket   <- TS `fmap` newMVar (OpenSocket accToCon conToAcc)
     putMVar mv thSocket
     return (mySocket, addr)

testLSocketClose :: ListenerTable -> TestListenSocket -> IO ()
testLSocketClose ltableIO tls =
  atomicModifyIORef' ltableIO (\ t -> (M.delete (tlsMyKey tls) t, ()))

-- -----------------------------------------------------------------------------

newtype TestSocket = TS (MVar TestSocketState)

data TestSocketState = ClosedSocket
                     | OpenSocket ByteChan ByteChan

testSocketFlush :: TestSocket -> IO ()
testSocketFlush ts@(TS stateMV) =
  do state <- readMVar stateMV
     case state of
       ClosedSocket   -> return ()
       OpenSocket _ w -> 
         do empty <- isEmptyByteChan w
            unless empty (testSocketFlush ts)

testSocketClose :: TestSocket -> IO ()
testSocketClose (TS stateMV) =
  modifyMVar_ stateMV (const (return ClosedSocket))

testSocketSend :: TestSocket -> L.ByteString -> IO ()
testSocketSend (TS stateMV) bstr =
  do state <- readMVar stateMV
     case state of
       ClosedSocket   -> fail "Write to closed socket."
       OpenSocket _ w -> mapM_ (writeByteChan w) (L.toChunks bstr)

testSocketRecv :: TestSocket -> Int -> IO S.ByteString
testSocketRecv (TS stateMV) x =
  do state <- readMVar stateMV
     case state of
       ClosedSocket   -> fail "Read from closed socket."
       OpenSocket r _ -> readByteChan r x

instance HasBackend TestSocket where
  initializeBackend = const (return ())
  getBackend s      = Backend {
      backendFlush = testSocketFlush s
    , backendClose = testSocketClose s
    , backendSend  = testSocketSend  s . L.fromStrict
    , backendRecv  = testSocketRecv  s
    }

-- -----------------------------------------------------------------------------

testSockets :: Test
testSockets =
  testGroup "Test socket code checks" [
    testByteChan
  , testProperty "Connect writes / accept reads" prop_connToAcc
  , testProperty "Accept writes / connect reads" prop_accToConn
  , testCase     "Flush actually blocks" flushFlushes
  ]

prop_xtoy :: (S.ByteString -> Word16 -> IO (S.ByteString, TorAddress)) ->
             S.ByteString -> Word16 ->
             Property
prop_xtoy action bstr port =
  monadicIO $
    do pre (S.length bstr > 0)
       pre (port > 0)
       (bstr', addr) <- run (action bstr port)
       assert (addr == IP4 "10.0.0.1")
       assert (bstr == bstr')

prop_connToAcc :: S.ByteString -> Word16 -> Property
prop_connToAcc = prop_xtoy runprop
 where
  runprop bstr port =
    do ltable  <- newIORef M.empty
       let ns  =  buildTestNetworkStack ltable M.empty (IP4"10.0.0.1")
       lsock   <- listen ns port
       askMV   <- newEmptyMVar
       _       <- forkIO (putMVar askMV =<< accept ns lsock)
       Just s  <- connect ns "10.0.0.1" port
       (ls, a) <- takeMVar askMV
       write ns s (L.fromStrict bstr)
       res     <- recv ns ls (fromIntegral (S.length bstr))
       return (res, a)

prop_accToConn :: S.ByteString -> Word16 -> Property
prop_accToConn = prop_xtoy runprop
 where
  runprop bstr port =
    do ltable  <- newIORef M.empty
       let ns  =  buildTestNetworkStack ltable M.empty (IP4"10.0.0.1")
       lsock   <- listen ns port
       askMV   <- newEmptyMVar
       _       <- forkIO (putMVar askMV =<< accept ns lsock)
       Just s  <- connect ns "10.0.0.1" port
       (ls, a) <- takeMVar askMV
       write ns ls (L.fromStrict bstr)
       res     <- recv ns s (fromIntegral (S.length bstr))
       return (res, a)

flushFlushes :: Assertion
flushFlushes =
    do ltable  <- newIORef M.empty
       let ns  =  buildTestNetworkStack ltable M.empty (IP4"10.0.0.1")
           bs  =  S.replicate 100 0
       lsock   <- listen ns 40
       askMV   <- newEmptyMVar
       _       <- forkIO (putMVar askMV =<< accept ns lsock)
       Just s  <- connect ns "10.0.0.1" 40
       (ls, _) <- takeMVar askMV
       write ns ls (L.fromStrict bs)
       _       <- recv ns s 50
       val     <- timeout 500000 (flush ns ls)
       assertEqual "Flush timed out" val Nothing

