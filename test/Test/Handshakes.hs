{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Test.Handshakes where

import Crypto.Hash
import Crypto.PubKey.Curve25519
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.Types
import Control.Applicative
import Control.Monad
import Crypto.Random
import Data.ByteArray(convert,eq)
import Data.ByteString(ByteString,pack)
import qualified Data.ByteString as BS
import Data.Word
import Hexdump
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck hiding (generate)
import Test.Standard
import Tor.State.Credentials
import Tor.HybridCrypto
import Tor.Circuit
import Tor.RouterDesc
import Tor.DataFormat.TorCell
import Tor.RNG

import Debug.Trace

data RouterTAP = RouterTAP RouterDesc PrivateKey
  deriving (Show)

instance Arbitrary RouterTAP where
  arbitrary =
    do g <- arbitrary :: Gen TorRNG
       let ((pub, priv), _) = withDRG g (generate (1024 `div` 8) 65537)
           desc = blankRouterDesc{ routerOnionKey = pub }
       return (RouterTAP desc priv)

instance Arbitrary TorRNG where
  arbitrary = drgNewTest `fmap` arbitrary

instance Show TorRNG where
  show _ = "TorRNG"

instance Eq (Context SHA1) where
  a == b = a `eq` b

instance Show (Context SHA1) where
  show x = simpleHex (convert x)

data RouterNTor = RouterNTor RouterDesc SecretKey
  deriving (Show)

instance Arbitrary RouterNTor where
  arbitrary =
    do g0 <- arbitrary :: Gen TorRNG
       let ((pub, priv), g1) = withDRG g0 generate25519
           (fprint, g2)      = withRandomBytes g1 20 id
           desc = blankRouterDesc{ routerFingerprint = fprint
                                 , routerNTorOnionKey = Just pub
                                 }
       return (RouterNTor desc priv)

tapHandshakeCheck :: Word32 -> RouterTAP -> TorRNG -> Bool
tapHandshakeCheck circId (RouterTAP myRouter priv) g0 =
  let (g1, (privX, cbody)) = startTAPHandshake myRouter g0
      (g2, (dcell, fenc, benc)) = advanceTAPHandshake priv circId cbody g1
      Created circIdD dbody = dcell
  in case completeTAPHandshake privX dbody of
       Left err ->
          False
       Right (fenc', benc') ->
         (circId == circIdD) && (fenc == fenc') && (benc == benc')

ntorHandshakeCheck :: Word32 -> RouterNTor -> TorRNG -> Bool
ntorHandshakeCheck circId (RouterNTor router littleB) g0 =
  case startNTorHandshake router g0 of
    (_, Nothing) ->
      False
    (g1, Just (pair, cbody)) ->
      case advanceNTorHandshake router littleB circId cbody g1 of
        (_, Left err) ->
          False
        (_, Right (Created2 _ dbody, fenc, benc)) ->
          case completeNTorHandshake router pair dbody of
            Left err ->
              False
            Right (fenc', benc') ->
              (fenc == fenc') && (benc == benc')

handshakeTests :: Test
handshakeTests =
  testGroup "Handshakes" [
    testProperty "TAP Handshake" tapHandshakeCheck
  , testProperty "NTor Handshake" ntorHandshakeCheck
  ]
