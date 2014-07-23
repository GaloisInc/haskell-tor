{-# LANGUAGE RecordWildCards #-}
module Test.DiffieHellman(diffieHellmanTests) where

import Codec.Crypto.RSA.Pure
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Either
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.HUnit hiding (Test)
import Test.Standard
import TLS.DiffieHellman

instance Arbitrary ServerDHParams where
  arbitrary =
    do plen <- choose (1, 16384)
       glen <- choose (1, plen)
       ylen <- choose (1, plen)
       dhP  <- bstrLen plen
       dhG  <- bstrLen glen
       dhYs <- bstrLen ylen
       return ServerDHParams{..}

instance Arbitrary ClientDiffieHellmanPublic where
  arbitrary = oneof [ return ClientDHImplicit
                    , ClientDHExplicit `fmap` (bstrLen =<< choose (1,65535))
                    ]

instance Arbitrary DiffieHellmanGroup where
  arbitrary = elements [oakley1, oakley2, modp1536, modp2048, modp3072,
                        modp4096, modp6144, modp8192]

-- ----------------------------------------------------------------------------

bstrLen :: Int -> Gen ByteString
bstrLen n =
  do first <- choose (1,255)
     rest  <- replicateM (n - 1) arbitrary
     return (BS.pack (first:rest))

-- ----------------------------------------------------------------------------

data GroupAndSecrets = GAS2 DiffieHellmanGroup Integer Integer
  deriving (Eq, Show)

instance Arbitrary GroupAndSecrets where
  arbitrary =
    do group  <- arbitrary
       rng    <- arbitraryRNG
       let local1 = generateLocal group rng
       case local1 of
         Left _ -> arbitrary
         Right (a, rng') ->
           do let local2 = generateLocal group rng'
              case local2 of
                Left _ -> arbitrary
                Right (b, _) ->
                  return (GAS2 group a b)

data GroupAndSecret = GAS DiffieHellmanGroup Integer
 deriving (Eq, Show)

instance Arbitrary GroupAndSecret where
  arbitrary =
    do group <- arbitrary
       rng   <- arbitraryRNG
       case generateLocal group rng of
         Left _       -> arbitrary
         Right (a, _) -> return (GAS group a)

prop_ClientDHInOut :: ClientDiffieHellmanPublic -> Bool
prop_ClientDHInOut x@ClientDHImplicit =
  let bstr = runPut (putClientDH x)
      y    = runGet (getClientDH Implicit) bstr
  in x == y
prop_ClientDHInOut x@ClientDHExplicit{} =
  let bstr = runPut (putClientDH x)
      y    = runGet (getClientDH Explicit) bstr
  in x == y

prop_groupParamsConversion :: ServerDHParams -> Bool
prop_groupParamsConversion dhp = dhp == dhp'
 where
  (dhg, ys) = serverDHParamsToGroup dhp
  dhp'      = groupToServerDHParams dhg ys

prop_canGoClient :: GroupAndSecret -> Bool
prop_canGoClient (GAS dhg v) =
  v == clientPublicToInteger (integerToClientPublic dhg v)

prop_localToServerConversion :: GroupAndSecret -> Bool
prop_localToServerConversion (GAS dhg a) = (dhg == dhg') && (a == a')
 where
  dhp        = groupToServerDHParams dhg a
  (dhg', a') = serverDHParamsToGroup dhp

prop_PublicValueOK :: GroupAndSecret -> Bool
prop_PublicValueOK (GAS dhg a) = isRight (i2osp p (dhgSize dhg))
 where p = computePublicValue dhg a

prop_ServerDHParamsInOut :: ServerDHParams -> Bool
prop_ServerDHParamsInOut = serialProp getServerDHParams putServerDHParams

prop_basicDHWorks :: GroupAndSecrets -> Bool
prop_basicDHWorks (GAS2 group a b) = leftS == rightS
 where
  g      = dhgG group
  p      = dhgP group
  bigA   = modular_exponentiation g a p
  bigB   = modular_exponentiation g b p
  leftS  = modular_exponentiation bigB a p
  rightS = modular_exponentiation bigA b p

appropriatelySized :: DiffieHellmanGroup -> Bool
appropriatelySized dhg =
  isRight (i2osp (dhgP dhg) (dhgSize dhg)) &&
  (dhgSize dhg `mod` 8 == 0)

diffieHellmanTests :: Test
diffieHellmanTests =
  testGroup "Diffie-Hellman Subsystem Tests" [
    testGroup "Built-in Groups Are Sane" [
      testCase "oakley1 group is sane"  (assertBool "" (appropriatelySized oakley1))
    , testCase "oakley2 group is sane"  (assertBool "" (appropriatelySized oakley2))
    , testCase "modp1536 group is sane" (assertBool "" (appropriatelySized modp1536))
    , testCase "modp2048 group is sane" (assertBool "" (appropriatelySized modp2048))
    , testCase "modp3072 group is sane" (assertBool "" (appropriatelySized modp3072))
    , testCase "modp4096 group is sane" (assertBool "" (appropriatelySized modp4096))
    , testCase "modp6144 group is sane" (assertBool "" (appropriatelySized modp6144))
    , testCase "modp8192 group is sane" (assertBool "" (appropriatelySized modp8192))
    ]
  , testGroup "Serialization / Conversion Tests" [
      testProperty "ServerDHParam serialization"
                   prop_ServerDHParamsInOut
    , testProperty "ClientDiffieHellmanPublic serialization"
                   prop_ClientDHInOut
    , testProperty "ServerDHParam / Integer conversion"
                   prop_groupParamsConversion
    , testProperty "Local / ServerDHParam conversion"
                   prop_localToServerConversion
    , testProperty "Internal / ClientDHExplicit conversion"
                   prop_canGoClient
    ]
  , testGroup "Functional Tests" [
      testProperty "Public value generation seems sane"
                   prop_PublicValueOK
    , testProperty "Basic DH exchange generates shared secret"
                   prop_basicDHWorks
    ]
  ]
