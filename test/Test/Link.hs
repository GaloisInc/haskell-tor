module Test.Link(linkTests)
 where

import Control.Concurrent.MVar(MVar, newMVar)
import Control.Exception(SomeException)
import Control.Monad(unless)
import Crypto.Random(drgNewTest)
import Data.Either(isRight)
import Data.Word(Word64)
import Test.Framework(Test, testGroup)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.Network(initializeInternet, createNode, routerDatabase)
import Test.QuickCheck(Property)
import Test.QuickCheck.Monadic(monadicIO, run, assert)
import Tor.DataFormat.TorAddress
import Tor.Link(initLink, acceptLink)
import Tor.NetworkStack(TorNetworkStack(..))
import Tor.Options(defaultTorOptions)
import Tor.RouterDesc(RouterDesc(..))

linkTests :: Test
linkTests =
  testGroup "Link-level tests" [
    testProperty "Link connections work" prop_linkConnect
  ]

prop_linkConnect :: (Word64, Word64, Word64, Word64, Word64) ->
                    Property
prop_linkConnect seed =
  monadicIO $ do internet             <- run $ initializeInternet seed
                 (descA, credsA, nsA) <- run $ createNode defaultTorOptions internet
                 (descB, credsB, nsB) <- run $ createNode defaultTorOptions internet
                 rdb                  <- run $ routerDatabase internet
                 rng                  <- run $ newMVar (drgNewTest seed)
                 results <- run $ parallelRun [
                              connectToB  nsA credsA rng descB
                            , acceptFromA nsB credsB rng descA descB rdb
                            ]
                 assert (all isRight results)
 where
  connectToB nsA credsA rng descB =
    initLink nsA credsA rng (const (return ())) descB
  acceptFromA nsB  credsB rng descA descB routerDB =
    do lsock        <- listen nsB (routerORPort descB)
       (sock, addr) <- accept nsB lsock
       case addr of
         IP4 a | routerIPv4Address descA /= a ->
           fail "Connection from wrong IP address?"
         IP4 a ->
           return ()
         _ ->
           fail "Connection from non-IP4 address?"
       acceptLink credsB routerDB rng (const (return ())) sock addr

parallelRun :: [IO a] -> IO [Either SomeException a]
parallelRun actions = undefined
