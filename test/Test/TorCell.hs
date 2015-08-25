{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards   #-}
module Test.TorCell(torCellTests) where

import Control.Monad
import Crypto.Hash
import Data.ASN1.OID
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteArray(convert)
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy  as BSL
import Data.ByteString.Lazy(toStrict,fromStrict)
import Data.Hourglass
import Data.List
import Data.String
import Data.Word
import Data.X509
import Numeric
import Test.QuickCheck
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.Standard
import Tor.DataFormat.RelayCell
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell
import Tor.State.Credentials

instance Arbitrary TorAddress where
  arbitrary = oneof [ Hostname <$> genHostname
                    , IP4 <$> genIP4
                    , IP6 <$> genIP6
                    , return (TransientError "External transient error.")
                    , return (NontransientError "External nontransient error.")
                    ]

genHostname :: Gen String
genHostname = take 255 <$> 
                intercalate "." <$>
                  (listOf (listOf (elements ['a'..'z'])))

genIP4 :: Gen String
genIP4 = intercalate "." <$>
           (replicateM 4 (show <$> (arbitrary :: Gen Word8)))

genIP6 :: Gen String
genIP6 = do x <- genIP6'
            return ("[" ++ intercalate ":" x ++ "]")
 where
  genIP6'     = map showHex' <$> 
                        replicateM 8 (arbitrary :: Gen Word16)

prop_TorAddrSerial :: TorAddress -> Bool
prop_TorAddrSerial  = serialProp getTorAddress putTorAddress

data TorAddressBS = TABS ByteString TorAddress
 deriving (Show, Eq)

instance Arbitrary TorAddressBS where
  arbitrary = oneof [ do x <- replicateM 4 arbitrary
                         let str = intercalate "." (map show x)
                             bstr = BS.pack x
                         return (TABS bstr (IP4 str))
                    , do x <- replicateM 16 arbitrary
                         let bstr = BSL.pack x
                             xs   = runGet (replicateM 8 getWord16be) bstr
                             str  = "[" ++ intercalate ":" (map showHex' xs) ++ "]"
                         return (TABS (toStrict bstr) (IP6 str))
                    ]

prop_TorAddrBSSerial :: TorAddressBS -> Bool
prop_TorAddrBSSerial (TABS bstr x) = bstr == torAddressByteString x

showHex' :: (Show a, Integral a) => a -> String
showHex' x = showHex x ""

instance Arbitrary ExtendSpec where
  arbitrary = oneof [ ExtendIP4 <$> (BS.pack <$> replicateM 4 arbitrary )
                                <*> arbitrary
                    , ExtendIP6 <$> (BS.pack <$> replicateM 16 arbitrary)
                                <*> arbitrary
                    , ExtendDigest <$>
                        (BSC.pack <$>
                           replicateM 20 (elements "abcdef0123456789"))
                    ]

prop_ExtendSpecSerial :: ExtendSpec -> Bool
prop_ExtendSpecSerial = serialProp getExtendSpec putExtendSpec

instance Arbitrary DestroyReason where
  arbitrary = elements [NoReason, TorProtocolViolation, InternalError,
                        RequestedDestroy, NodeHibernating, HitResourceLimit,
                        ConnectionFailed, ORIdentityIssue, ORConnectionClosed,
                        Finished, CircuitConstructionTimeout, CircuitDestroyed,
                        NoSuchService]

prop_DestroyReasonSerial1 :: DestroyReason -> Bool
prop_DestroyReasonSerial1 = serialProp getDestroyReason putDestroyReason

prop_DestroyReasonSerial2 :: Word8 -> Bool
prop_DestroyReasonSerial2 x =
  [x] == BSL.unpack (runPut (putDestroyReason
                       (runGet getDestroyReason (BSL.pack [x]))))

instance Arbitrary RelayEndReason where
  arbitrary = oneof [ ReasonExitPolicy <$> (IP4 <$> genIP4) <*> arbitrary
                    , ReasonExitPolicy <$> (IP6 <$> genIP6) <*> arbitrary
                    , elements [ReasonMisc, ReasonResolveFailed,
                        ReasonConnectionRefused, ReasonDestroyed, ReasonDone,
                        ReasonTimeout, ReasonNoRoute, ReasonHibernating,
                        ReasonInternal, ReasonResourceLimit,
                        ReasonConnectionReset, ReasonTorProtocol,
                        ReasonNotDirectory ]
                    ]

prop_RelayEndRsnSerial :: RelayEndReason -> Bool
prop_RelayEndRsnSerial rsn =
  let bstr = runPut (putRelayEndReason rsn)
      len  = case rsn of
               ReasonExitPolicy (IP4 _) _ -> 9
               ReasonExitPolicy (IP6 _) _ -> 21
               _                          -> 1
      rsn' = runGet (getRelayEndReason len) bstr
  in rsn == rsn'

instance Arbitrary RelayCell where
  arbitrary =
   oneof [ RelayBegin <$> arbitrary <*> legalTorAddress True
                      <*> arbitrary <*> arbitrary <*> arbitrary
                      <*> arbitrary
         , RelayData <$> arbitrary
                     <*> ((BS.pack . take 503) <$> arbitrary)
         , RelayEnd <$> arbitrary <*> arbitrary
         , RelayConnected <$> arbitrary <*> legalTorAddress False
                          <*> arbitrary
         , RelaySendMe <$> arbitrary
         , RelayExtend <$> arbitrary <*> (IP4 <$> genIP4)
                       <*> arbitrary <*> arbitraryBS 186 <*> arbitraryBS 20
         , RelayExtended <$> arbitrary
                         <*> (BS.pack <$> replicateM 148 arbitrary)
         , RelayTruncate <$> arbitrary
         , RelayTruncated <$> arbitrary <*> arbitrary
         , RelayDrop <$> arbitrary
         , RelayResolve <$> arbitrary
                        <*> (filter (/= '\0') <$> arbitrary)
         , do strm <- arbitrary
              vals <- listOf $ do x <- legalTorAddress True
                                  y <- arbitrary
                                  return (x,y)
              return (RelayResolved strm vals)
         , RelayBeginDir <$> arbitrary
         , RelayExtend2 <$> arbitrary <*> arbitrary <*> arbitrary
                        <*> (BS.pack <$> arbitrary)
         , RelayExtended2 <$> arbitrary <*> (BS.pack <$> arbitrary)
         , RelayEstablishIntro <$> arbitrary <*> arbitraryBS 128
                               <*> arbitraryBS 20 <*> arbitraryBS 128
         , RelayEstablishRendezvous <$> arbitrary <*> arbitraryBS 20
         , RelayIntroduce1 <$> arbitrary <*> arbitraryBS 20
                           <*> (BS.pack <$> arbitrary)
         , RelayIntroduce2 <$> arbitrary <*> (BS.pack <$> arbitrary)
         , RelayRendezvous1 <$> arbitrary <*> arbitraryBS 20
                            <*> arbitraryBS 128 <*> arbitraryBS 20
         , RelayRendezvous2 <$> arbitrary <*> arbitraryBS 128
                            <*> arbitraryBS 20
         , RelayIntroEstablished <$> arbitrary
         , RelayRendezvousEstablished <$> arbitrary
         , RelayIntroduceAck <$> arbitrary
         ]

legalTorAddress :: Bool -> Gen TorAddress
legalTorAddress allowHostname =
  do x <- arbitrary
     case x of
       Hostname ""                 -> legalTorAddress allowHostname
       Hostname _  | allowHostname -> return x
       IP4      "0.0.0.0"          -> legalTorAddress allowHostname
       IP4      _                  -> return x
       IP6      _                  -> return x
       _                           -> legalTorAddress allowHostname

prop_RelayCellSerial :: RelayCell -> Property
prop_RelayCellSerial x =
  let (_, gutsBS) = runPutM (putRelayCellGuts x)
      bstr        = runPut (putRelayCell (BS.replicate 4 0) x)
      (_, y)      = runGet getRelayCell bstr
  in (BSL.length gutsBS <= (509 - 11)) ==> (x == y)

prop_RelayCellDigestWorks1 :: RelayCell -> Property
prop_RelayCellDigestWorks1 x =
  let (_, gutsBS) = runPutM (putRelayCellGuts x)
      (bstr, _)   = renderRelayCell hashInit x
      (x',   _)   = runGet (parseRelayCell hashInit) (fromStrict bstr)
  in (BSL.length gutsBS <= (509 - 11)) ==> (x == x')

prop_RelayCellDigestWorks2 :: NonEmptyList RelayCell -> Property
prop_RelayCellDigestWorks2 xs =
  let mxSize = maximum (map putGuts (getNonEmpty xs))
      xs'    = runCheck hashInit hashInit (getNonEmpty xs)
  in (mxSize <= (509 - 11)) ==> (getNonEmpty xs == xs')
 where
  putGuts x =
    let (_, gutsBS) = runPutM (putRelayCellGuts x)
    in BSL.length gutsBS
  runCheck _ _ [] = []
  runCheck rstate pstate (f:rest) =
    let (bstr, rstate') = renderRelayCell rstate f
        (f',   pstate') = runGet (parseRelayCell pstate) (fromStrict bstr)
    in f' : runCheck rstate' pstate' rest

instance Arbitrary HandshakeType where
  arbitrary = elements [TAP, Reserved, NTor]

prop_HandTypeSerial1 :: HandshakeType -> Bool
prop_HandTypeSerial1 = serialProp getHandshakeType putHandshakeType

prop_HandTypeSerial2 :: Word16 -> Bool
prop_HandTypeSerial2 x =
  let ht = runGet getHandshakeType (runPut (putWord16be x))
  in runPut (putWord16be x) == runPut (putHandshakeType ht)

instance Arbitrary (SignedExact Certificate) where
  arbitrary =
    do certVersion      <- arbitrary
       certSerial       <- arbitrary
       certIssuerDN     <- arbitrary
       certSubjectDN    <- arbitrary
       hashAlg          <- elements [HashSHA1, HashSHA256, HashSHA384]

       g  <- arbitraryRNG
       let (pub, _, _) = generateKeyPair g 1024

       let keyAlg           = PubKeyALG_RSA -- FIXME?
           certSignatureAlg = SignatureALG hashAlg keyAlg
           certValidity     = (timeFromElapsed (Elapsed (Seconds 257896558)),
                               timeFromElapsed (Elapsed (Seconds 2466971758)))
           certPubKey       = PubKeyRSA pub
           certExtensions   = Extensions Nothing

       let baseCert = Certificate{ .. }
           sigfun   = case hashAlg of
                        HashSHA1   -> wrapSignatureAlg certSignatureAlg sha1
                        HashSHA224 -> wrapSignatureAlg certSignatureAlg sha224
                        HashSHA256 -> wrapSignatureAlg certSignatureAlg sha256
                        HashSHA384 -> wrapSignatureAlg certSignatureAlg sha384
                        HashSHA512 -> wrapSignatureAlg certSignatureAlg sha512
                        _          -> error "INTERNAL WEIRDNESS"
       let (signedCert, _) = objectToSignedExact sigfun baseCert
       return signedCert

newtype ReadableStr = ReadableStr { unReadableStr :: String }

instance Show ReadableStr where
  show = show . unReadableStr

instance Arbitrary ReadableStr where
  arbitrary =
    do len <- choose (1, 256)
       str <- replicateM len (elements printableChars)
       return (ReadableStr str)
   where printableChars = ['a'..'z'] ++ ['A'..'Z'] ++ ['_','.',' ']

instance Arbitrary DistinguishedName where
  arbitrary =
    do cn <- unReadableStr <$> arbitrary
       co <- unReadableStr <$> arbitrary
       og <- unReadableStr <$> arbitrary
       ou <- unReadableStr <$> arbitrary
       return (DistinguishedName [
                 (getObjectID DnCommonName,       fromString cn)
               , (getObjectID DnCountry,          fromString co)
               , (getObjectID DnOrganization,     fromString og)
               , (getObjectID DnOrganizationUnit, fromString ou)
               ])

wrapSignatureAlg :: SignatureALG ->
                    (ByteString -> ByteString) ->
                    ByteString ->
                    (ByteString, SignatureALG, ())
wrapSignatureAlg name sha bstr =
  let hashed   = convert (sha bstr)
  in (hashed, name, ())

sha1 :: ByteString -> ByteString
sha1 = convert . hashWith SHA1

sha224 :: ByteString -> ByteString
sha224 = convert . hashWith SHA224

sha256 :: ByteString -> ByteString
sha256 = convert . hashWith SHA256

sha384 :: ByteString -> ByteString
sha384 = convert . hashWith SHA384

sha512 :: ByteString -> ByteString
sha512 = convert . hashWith SHA512


instance Arbitrary TorCert where
  arbitrary = oneof [ LinkKeyCert     <$> arbitrary
                    , RSA1024Identity <$> arbitrary
                    , RSA1024Auth     <$> arbitrary
                    ]

prop_torCertSerial :: TorCert -> Bool
prop_torCertSerial = serialProp getTorCert putTorCert

torCellTests :: Test
torCellTests =
  testGroup "TorCell Serialization" [
    testProperty "TorAddress round-trips" prop_TorAddrSerial
  , testProperty "TorAddress makes sensible ByteStrings" prop_TorAddrBSSerial
  , testProperty "ExtendSpec serializes" prop_ExtendSpecSerial
  , testProperty "DestroyReason serializes (check #1)" prop_DestroyReasonSerial1
  , testProperty "DestroyReason serializes (check #2)" prop_DestroyReasonSerial2
  , testProperty "HandshakeType serializes (check #1)" prop_HandTypeSerial1
  , testProperty "HandshakeType serializes (check #2)" prop_HandTypeSerial2
  , testProperty "RelayEndReason serializes" prop_RelayEndRsnSerial
  , testProperty "RelayCell serializes" prop_RelayCellSerial
  , testProperty "RelayCell serializes w/ digest" prop_RelayCellDigestWorks1
  , testProperty "RelayCell serializes w/ digest" prop_RelayCellDigestWorks2
  , testProperty "Tor certificates serialize" prop_torCertSerial
  ]

