{-# LANGUAGE RecordWildCards #-}
module Test.Network(
         Internet
       , InternetSeed
       , initializeInternet
       , Node(..)
       , createNode
       , routerDatabase
       , getRNG
       --
       , testTestInternet
       )
 where

import           Control.Concurrent(forkIO)
import           Control.Concurrent.MVar(MVar, newMVar, withMVar, modifyMVar)
import           Control.Concurrent.MVar(newEmptyMVar, takeMVar, putMVar)
import           Crypto.Random(ChaChaDRG, drgNewTest, randomBytesGenerate)
import           Data.Bits(shiftL)
import           Data.ByteArray(Bytes)
import qualified Data.ByteArray as Mem
import           Data.ByteString(ByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.List(intercalate)
import           Data.Map.Strict(Map)
import qualified Data.Map.Strict as M
import           Data.Word(Word64, Word16)
import           Test.Framework(Test, testGroup)
import           Test.Framework.Providers.QuickCheck2(testProperty)
import           Test.Network.Socket(TestNetworkStack, buildTestNetworkStack)
import           Test.Network.Socket(ListenerTable, newListenerTable)
import           Test.Network.Socket(TestSocket, testSockets)
import           Test.QuickCheck(Arbitrary(..), Property)
import           Test.QuickCheck.Monadic(PropertyM, monadicIO, run, pre, assert)
import           Test.Standard(testOptions)
import           Tor.DataFormat.TorAddress(TorAddress(..))
import           Tor.NetworkStack(TorNetworkStack(..))
import           Tor.Options(TorOptions(..))
import           Tor.RouterDesc(RouterDesc(..), blankRouterDesc)
import           Tor.State.Credentials(Credentials, newCredentials)
import           Tor.State.Routers(RouterDB, newTestRouterDatabase)

data Internet = Internet {
       inRNG           :: MVar ChaChaDRG
     , inNodes         :: MVar (Map String Node)
     , inListenerTable :: ListenerTable
     }

newtype InternetSeed = Seed (Word64, Word64, Word64, Word64, Word64)
 deriving (Eq, Show)

instance Arbitrary InternetSeed where
  arbitrary = Seed `fmap` arbitrary

data Node = Node {
       nodeRouterDesc   :: RouterDesc
     , nodeCredentials  :: Credentials
     , nodeNetworkStack :: TestNetworkStack
     }

initializeInternet :: InternetSeed -> IO Internet
initializeInternet (Seed seed) =
  do inRNG           <- newMVar (drgNewTest seed)
     inNodes         <- newMVar M.empty
     inListenerTable <- newListenerTable
     return Internet{..}

routerDatabase :: Internet -> IO RouterDB
routerDatabase internet =
  withMVar (inNodes internet) $
    newTestRouterDatabase . map nodeRouterDesc . M.elems

getRNG :: Internet -> MVar ChaChaDRG
getRNG = inRNG

createNode :: Internet -> TorOptions ->
              IO (RouterDesc, Credentials, TestNetworkStack)
createNode internet torOpts =
  modifyMVar (inRNG internet) $ \ rng ->
    modifyMVar (inNodes internet) $ \ nodes ->
      do (rng',  addr) <- findNewAddress rng nodes
         (rng'', port) <- getPort rng'
         creds         <- newCredentials torOpts
         let ltable    =  inListenerTable internet
             ns        =  buildTestNetworkStack ltable M.empty (IP4 addr)
             desc      =  blankRouterDesc{ routerIPv4Address = addr
                                         , routerORPort      = min 1 port
                                         }
             nodes'    =  M.insert addr (Node desc creds ns) nodes
         return (nodes', (rng'', (desc, creds, ns)))
 where
  findNewAddress rng nodes =
    do let (arr, rng') = randomBytesGenerate 4 rng
           addr        = intercalate "." (map show (Mem.unpack (arr :: Bytes)))
       if M.member addr nodes
          then findNewAddress rng' nodes
          else return (rng', addr)
  --
  getPort rng =
    do let (arr, rng') = randomBytesGenerate 2 rng
           [a,b]       = map fromIntegral (Mem.unpack (arr :: Bytes))
       return (rng', (a `shiftL` 8) + b)

-- -----------------------------------------------------------------------------

testTestInternet :: Test
testTestInternet =
  testGroup "Test internet checks" [
    testSockets
  , testProperty "Internet connect writes" prop_connectWrites
  , testProperty "Internet accept writes"   prop_acceptWrites
  , testProperty "Internet multiple connect writes" prop_mconnectWrites
  , testProperty "Internet multiple accept writes"   prop_macceptWrites
  ]

prop_connectWrites :: ByteString -> InternetSeed -> Word16 -> Property
prop_connectWrites bstr = twoNodeProp $ \ (_, ns1, s1) (_, ns2, s2) ->
  do let len = fromIntegral (S.length bstr)
     pre (len > 0)
     run (write ns1 s1 (L.fromStrict bstr))
     bstr' <- run (recv ns2 s2 len)
     assert (bstr == bstr')

prop_acceptWrites :: ByteString -> InternetSeed -> Word16 -> Property
prop_acceptWrites bstr = twoNodeProp $ \ (_, ns1, s1) (_, ns2, s2) ->
  do let len = fromIntegral (S.length bstr)
     pre (len > 0)
     run (write ns2 s2 (L.fromStrict bstr))
     bstr' <- run (recv ns1 s1 len)
     assert (bstr == bstr')

prop_mconnectWrites :: [ByteString] -> InternetSeed -> Word16 -> Property
prop_mconnectWrites bstrs = twoNodeProp $ \ (_, ns1, s1) (_, ns2, s2) ->
  do let bstrs' = filter (not . S.null) bstrs
         len    = sum (map (fromIntegral . S.length) bstrs')
     run (mapM_ (write ns1 s1 . L.fromStrict) bstrs')
     bstrs'' <- run (recv ns2 s2 len)
     assert (S.concat bstrs' == bstrs'')

prop_macceptWrites :: [ByteString] -> InternetSeed -> Word16 -> Property
prop_macceptWrites bstrs = twoNodeProp $ \ (_, ns1, s1) (_, ns2, s2) ->
  do let bstrs' = filter (not . S.null) bstrs
         len    = sum (map (fromIntegral . S.length) bstrs')
     run (mapM_ (write ns2 s2 . L.fromStrict) bstrs')
     bstrs'' <- run (recv ns1 s1 len)
     assert (S.concat bstrs' == bstrs'')

type Connection = (String, TestNetworkStack, TestSocket)

twoNodeProp :: (Connection -> Connection -> PropertyM IO a) ->
               InternetSeed -> Word16 ->
               Property
twoNodeProp doProperty seed port =
  monadicIO $
   do internet <- run (initializeInternet seed)
      (d1, _, ns1) <- run (createNode internet testOptions)
      (d2, _, ns2) <- run (createNode internet testOptions)
      let addr1 = routerIPv4Address d1
          addr2 = routerIPv4Address d2
      assert (addr1 /= addr2)
      lsock            <- run (listen ns1 port)
      askMV            <- run newEmptyMVar
      _                <- run (forkIO (putMVar askMV =<< accept ns1 lsock))
      Just connSock    <- run (connect ns2 addr1 port)
      (accSock, addr3) <- run (takeMVar askMV)
      assert (addr3 == IP4 addr2)
      doProperty (addr1, ns1, accSock) (addr2, ns2, connSock)
