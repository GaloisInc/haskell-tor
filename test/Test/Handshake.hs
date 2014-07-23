{-# LANGUAGE ExistentialQuantification #-}
module Test.Handshake(handshakeTests) where

import Control.Applicative
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString.Lazy as BS
import Test.Certificate()
import Test.CipherSuite()
import Test.ClientCertificateType()
import Test.CompressionMethod()
import Test.DiffieHellman()
import Test.DistinguishedName()
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.HashAlgorithm()
import Test.KeyExchangeAlgorithm()
import Test.ProtocolVersion()
import Test.SignatureAlgorithm()
import Test.QuickCheck
import Test.Random()
import Test.Session()
import Test.Standard
import TLS.CipherSuite
import TLS.CipherSuite.KeyExchangeAlgorithm
import TLS.CompressionMethod
import TLS.Handshake
import TLS.Handshake.Certificate
import TLS.Handshake.CertificateRequest
import TLS.Handshake.CertificateVerify
import TLS.Handshake.ClientKeyExchange
import TLS.Handshake.ClientHello
import TLS.Handshake.Extension
import TLS.Handshake.Finished
import TLS.Handshake.HelloRequest
import TLS.Handshake.ServerHello
import TLS.Handshake.ServerHelloDone
import TLS.Handshake.ServerKeyExchange
import TLS.Handshake.Type
import TLS.ProtocolVersion

instance Arbitrary HandshakeType where
  arbitrary = elements [TypeHelloRequest, TypeClientHello, TypeServerHello,
                        TypeCertificate, TypeServerKeyExchange,
                        TypeCertificateRequest, TypeServerHelloDone,
                        TypeCertificateVerify, TypeClientKeyExchange,
                        TypeFinished]

instance Arbitrary Extension where
  arbitrary = oneof [ do a <- arbitrary
                         b <- arbitrary
                         c <- arbitrary
                         return (ExtSignatureAlgorithm ([a,b] ++ c))
                    , do b <- BS.pack <$> arbitrary
                         let pickNot xs = do t <- arbitrary
                                             if t `elem` xs
                                               then pickNot xs
                                               else return t
                         t <- pickNot [13]
                         return (ExtUnknown t b)
                    ]


instance Arbitrary Certificate where
  arbitrary =
   do len <- choose (1,2)
      Certificate <$> replicateM len arbitrary

instance Arbitrary CertificateRequest where
  arbitrary = CertificateRequest <$> (getNonEmpty <$> arbitrary)
                                 <*> (do x <- arbitrary
                                         case x of
                                           [] -> return Nothing
                                           xs -> return (Just xs))
                                 <*> arbitrary

instance Arbitrary CertificateVerify where
  arbitrary = CertificateVerify <$> arbitrary <*> arbitrary
                                <*> (BS.pack <$> arbitrary)

instance Arbitrary ClientHello where
  arbitrary = ClientHello <$> arbitrary <*> arbitrary <*> arbitrary
                          <*> (do a <- arbitrary
                                  b <- arbitrary
                                  ([a,b] ++) <$> arbitrary)
                          <*> (getNonEmpty <$> arbitrary)
                          <*> arbitrary

instance Arbitrary ClientKeyExchange where
  arbitrary = oneof [ (ClientKeyExchangeEncrypt . BS.pack) <$> arbitrary
                    , return ClientKeyExchangeDHImplicit
                    , (ClientKeyExchangeDHExplicit . BS.pack . getNonEmpty)
                         <$> arbitrary ]

instance Arbitrary Finished where
  arbitrary = Finished <$> ((BS.pack . getNonEmpty) <$> arbitrary)

instance Arbitrary HelloRequest where
  arbitrary = return HelloRequest

instance Arbitrary ServerHello where
  arbitrary = ServerHello <$> arbitrary <*> arbitrary <*> arbitrary
                          <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ServerHelloDone where
  arbitrary = return ServerHelloDone

instance Arbitrary ServerKeyExchange where
  arbitrary = oneof [ ServerKeyExchangeAnon <$> arbitrary
                    , ServerKeyExchangeSigned  <$> arbitrary
                                               <*> arbitrary
                                               <*> arbitrary
                                               <*> (BS.pack <$> arbitrary) ]

instance Arbitrary RawHandshake where
  arbitrary = RawHandshake <$> arbitrary <*> ((BS.pack . take 16777215) <$> arbitrary)

data ArbHandshake = forall a b. IsHandshake a b => ArbHand a b

instance Show ArbHandshake where
  show (ArbHand x y) = "ArbHand " ++ show x ++ " " ++ show y

instance Arbitrary ArbHandshake where
  arbitrary = oneof [ ArbHand <$> (arbitrary :: Gen HelloRequest)      <*> runit
                    , ArbHand <$> (arbitrary :: Gen ClientHello)       <*> runit
                    , ArbHand <$> (arbitrary :: Gen ServerHello)       <*> runit
                    , ArbHand <$> (arbitrary :: Gen Certificate)       <*> runit
                    , do ske <- arbitrary
                         case ske of
                           ServerKeyExchangeAnon _ ->
                             return (ArbHand ske suiteTLS_DH_anon_WITH_AES_256_CBC_SHA)
                           _ ->
                             ArbHand ske <$> elements [suiteTLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                                       suiteTLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA]
                    , do cr  <- arbitrary
                         sas <- getNonEmpty <$> arbitrary
                         pv  <- arbitrary
                         let ssas = if pv < versionTLS1_2 then Nothing else Just sas
                         return (ArbHand cr{crSupportedSignatureAlgorithms = ssas} pv)
                    , ArbHand <$> (arbitrary :: Gen ServerHelloDone)   <*> runit
                    , ArbHand <$> (arbitrary :: Gen CertificateVerify) <*> runit
                    , do cke <- arbitrary
                         case cke of
                           ClientKeyExchangeEncrypt _ ->
                             return (ArbHand cke ExchRSA)
                           _ ->
                             do exch <- arbitrary `suchThat` (/= ExchRSA)
                                return (ArbHand cke exch)
                    , ArbHand <$> (arbitrary :: Gen Finished)          <*> runit
                    ]
   where runit = return ()

-- ----------------------------------------------------------------------------

prop_handshakeTypeSerializes :: HandshakeType -> Bool
prop_handshakeTypeSerializes = serialProp getHandshakeType putHandshakeType

prop_ExtensionSerializes :: Extension -> Bool
prop_ExtensionSerializes = serialProp getExtension putExtension

prop_certificateSerializes :: Certificate -> Bool
prop_certificateSerializes = serialProp getCertificate putCertificate

prop_CertReqSerial :: CertificateRequest -> Bool
prop_CertReqSerial x =
  let bstr = runPut (putCertificateRequest x)
      vers = case crSupportedSignatureAlgorithms x of
               Nothing -> versionTLS1_1
               Just _  -> versionTLS1_2
      y    = runGet (getCertificateRequest vers) bstr
  in x == y

prop_CertVerSerializes :: CertificateVerify -> Bool
prop_CertVerSerializes = serialProp getCertificateVerify putCertificateVerify

prop_clientHelloSerializes :: ClientHello -> Bool
prop_clientHelloSerializes =
  serialProp (getClientHello rfc5246CipherSuites rfc5246CompressionMethods)
             putClientHello

prop_CKESerial :: ClientKeyExchange -> KeyExchangeAlgorithm -> Bool
prop_CKESerial x@(ClientKeyExchangeEncrypt _) _ =
  serialProp (getClientKeyExchange ExchRSA) putClientKeyExchange x
prop_CKESerial _ ExchRSA =
  True
prop_CKESerial x kea =
  serialProp (getClientKeyExchange kea) putClientKeyExchange x

prop_FinishedSerializes :: Finished -> Bool
prop_FinishedSerializes = serialProp getFinished putFinished

prop_HelloReqSerializes :: HelloRequest -> Bool
prop_HelloReqSerializes = serialProp getHelloRequest putHelloRequest

prop_serverHelloSerializes :: ServerHello -> Bool
prop_serverHelloSerializes =
  serialProp (getServerHello rfc5246CipherSuites rfc5246CompressionMethods)
             putServerHello

prop_ServerHelloDoneSerial :: ServerHelloDone -> Bool
prop_ServerHelloDoneSerial = serialProp getServerHelloDone putServerHelloDone

prop_SKESerial :: ServerKeyExchange -> Bool -> Bool
prop_SKESerial x@(ServerKeyExchangeAnon _) _ =
  let bstr   = runPut (putServerKeyExchange x)
      cipher = suiteTLS_DH_anon_WITH_AES_256_CBC_SHA256
      y      = runGet (getServerKeyExchange cipher) bstr
  in x == y
prop_SKESerial x@(ServerKeyExchangeSigned _ _ _ _) isDSS =
  let bstr   = runPut (putServerKeyExchange x)
      cipher = if isDSS
                 then suiteTLS_DHE_DSS_WITH_AES_256_CBC_SHA256
                 else suiteTLS_DHE_RSA_WITH_AES_256_CBC_SHA256
      y      = runGet (getServerKeyExchange cipher) bstr
  in x == y

prop_HandshakeEncode :: ArbHandshake -> Bool
prop_HandshakeEncode (ArbHand x ctxt) =
  case decodeHandshake ctxt (encodeHandshake x) of
    Left _  -> False
    Right y -> x == y

prop_HandshakeSer :: RawHandshake -> Bool
prop_HandshakeSer = serialProp getRawHandshake putRawHandshake

-- ----------------------------------------------------------------------------

handshakeTests :: Test
handshakeTests =
  testGroup "Handshake tests" [
    testProperty "HandshakeType serializes" prop_handshakeTypeSerializes
  , testProperty "Extension serializes" prop_ExtensionSerializes
  , testProperty "Certificate serializes" prop_certificateSerializes
  , testProperty "CertificateRequest Serializes" prop_CertReqSerial
  , testProperty "CertificateVerify serializes" prop_CertVerSerializes
  , testProperty "ClientHello serializes" prop_clientHelloSerializes
  , testProperty "ClientKeyExchange serializes" prop_CKESerial
  , testProperty "Finished serializes" prop_FinishedSerializes
  , testProperty "HelloRequest serializes" prop_HelloReqSerializes
  , testProperty "ServerHello serializes" prop_serverHelloSerializes
  , testProperty "ServerHelloDone serializes" prop_ServerHelloDoneSerial
  , testProperty "ServerKeyExchange serializes" prop_SKESerial
  , testProperty "Generalized Handshake encoding works" prop_HandshakeEncode
  , testProperty "Generalized Handshake serialization works" prop_HandshakeSer
  ]
