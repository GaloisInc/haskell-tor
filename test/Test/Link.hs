module Test.Link(testLinks)
 where

import Control.Concurrent.Async(async, waitBoth)
import Test.Framework(Test, testGroup)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.Network(InternetSeed, testTestInternet)
import Test.Network(initializeInternet, createNode, routerDatabase, getRNG)
import Test.QuickCheck(Property)
import Test.QuickCheck.Monadic(monadicIO, run, assert)
import Test.Standard(testOptions)
import Tor.DataFormat.TorAddress
import Tor.Link(initLink, acceptLink)
import Tor.NetworkStack(TorNetworkStack(..))
import Tor.RouterDesc(RouterDesc(..))

testLinks :: Test
testLinks =
  testGroup "Link-level tests" [
    testTestInternet
  , testProperty "Link connections work" prop_linkConnect
  ]

prop_linkConnect :: InternetSeed -> Property
prop_linkConnect seed =
  monadicIO $
    do internet             <- run (initializeInternet seed)
       (descA, credsA, nsA) <- run (createNode internet testOptions)
       (descB, credsB, nsB) <- run (createNode internet testOptions)
       rdb                  <- run (routerDatabase internet)
       cona <- run (async (connectToB  nsA credsA (getRNG internet) descB))
       acca <- run (async (acceptFromA nsB credsB (getRNG internet) descA descB rdb))
       _    <- run (waitBoth cona acca)
       assert True -- An exception would be thrown if there was a problem
 where
  connectToB nsA credsA rng descB =
    initLink nsA credsA rng (const (return ())) descB
  acceptFromA nsB  credsB rng descA descB routerDB =
    do lsock        <- listen nsB (routerORPort descB)
       (sock, addr) <- accept nsB lsock
       case addr of
         IP4 a | routerIPv4Address descA /= a ->
           fail "Connection from wrong IP address?"
         IP4 _ ->
           return ()
         _ ->
           fail "Connection from non-IP4 address?"
       acceptLink credsB routerDB rng (const (return ())) sock addr
