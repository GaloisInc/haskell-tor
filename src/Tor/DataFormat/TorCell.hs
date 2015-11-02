{-# LANGUAGE DeriveDataTypeable #-}
module Tor.DataFormat.TorCell(
         TorCell(..),       putTorCell,       getTorCell
       , DestroyReason(..), putDestroyReason, getDestroyReason
       , HandshakeType(..), putHandshakeType, getHandshakeType
       , TorCert(..),       putTorCert,       getTorCert
       , getCircuit
       , isPadding
       )
 where

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative
#endif
import Control.Exception
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Typeable
import Data.X509
import Data.Word
import Tor.DataFormat.TorAddress

data TorCell = Padding
             | Create      Word32 ByteString
             | Created     Word32 ByteString
             | Relay       Word32 ByteString
             | Destroy     Word32 DestroyReason
             | CreateFast  Word32 ByteString
             | CreatedFast Word32 ByteString ByteString
             | NetInfo            Word32 TorAddress [TorAddress]
             | RelayEarly  Word32 ByteString
             | Create2     Word32 HandshakeType ByteString
             | Created2    Word32 ByteString
             | Versions
             | VPadding           ByteString
             | Certs              [TorCert]
             | AuthChallenge      ByteString [Word16]
             | Authenticate       ByteString
             | Authorize
 deriving (Eq, Show)

getCircuit :: TorCell -> Maybe Word32
getCircuit x =
  case x of
    Create      circId _   -> Just circId
    Created     circId _   -> Just circId
    Relay       circId _   -> Just circId
    Destroy     circId _   -> Just circId
    CreateFast  circId _   -> Just circId
    CreatedFast circId _ _ -> Just circId
    RelayEarly  circId _   -> Just circId
    Create2     circId _ _ -> Just circId
    Created2    circId _   -> Just circId
    _                      -> Nothing

isPadding :: TorCell -> Bool
isPadding x =
  case x of
    Padding    -> True
    VPadding _ -> True
    _          -> False

getTorCell :: Get TorCell
getTorCell =
  do circuit <- getWord32be
     command <- getWord8
     case command of
       0   -> getStandardCell $ return Padding
       1   -> getStandardCell $
                Create circuit <$> getByteString (128 + 16 + 42)
       2   -> getStandardCell $
                Created circuit <$> getByteString (128 + 20)
       3   -> getStandardCell $ Relay circuit <$> getByteString 509
       4   -> getStandardCell $ Destroy circuit <$> getDestroyReason
       5   -> getStandardCell $ CreateFast circuit <$> getByteString 20
       6   -> getStandardCell $ CreatedFast circuit <$> getByteString 20
                                                    <*> getByteString 20
       8   -> getStandardCell $
                do tstamp   <- getWord32be
                   otherOR  <- getTorAddress
                   numAddrs <- getWord8
                   thisOR   <- replicateM (fromIntegral numAddrs) getTorAddress
                   return (NetInfo tstamp otherOR thisOR)
       9   -> getStandardCell $ RelayEarly circuit <$> getByteString 509
       10  -> getStandardCell $
                do htype <- getHandshakeType
                   hlen  <- getWord16be
                   hdata <- getByteString (fromIntegral hlen)
                   return (Create2 circuit htype hdata)
       11  -> getStandardCell $
                do hlen  <- getWord16be
                   hdata <- getByteString (fromIntegral hlen)
                   return (Created2 circuit hdata)
       7   -> fail "Should not be getting versions through this interface."
       128 -> getVariableLength "VPadding"      getVPadding
       129 -> getVariableLength "Certs"         getCerts
       130 -> getVariableLength "AuthChallenge" getAuthChallenge
       131 -> getVariableLength "Authenticate"  getAuthenticate
       132 -> getVariableLength "Authorize"     (\ _ -> return Authorize)
       _   -> fail "Improper Tor cell command."
 where
  getStandardCell getter =
    do bstr <- getByteString 509 -- PAYLOAD_LEN
       case runGetOrFail getter (BSL.fromStrict bstr) of
         Left (_, _, err) -> fail err
         Right (_, _, x)  -> return x
  getVariableLength name getter =
    do len   <- getWord16be
       body  <- getByteString (fromIntegral len)
       case runGetOrFail (getter len) (BSL.fromStrict body) of
         Left  (_, _, s) -> fail ("Couldn't read " ++ name ++ " body: " ++ s)
         Right (_, _, x) -> return x
  --
  getVPadding len = VPadding <$> getByteString (fromIntegral len)
  --
  getAuthChallenge _ =
    do challenge <- getByteString 32
       n_methods <- getWord16be
       methods   <- replicateM (fromIntegral n_methods) getWord16be
       return (AuthChallenge challenge methods)
  --
  getAuthenticate _ =
    do _ <- getWord16be -- AuthType
       l <- getWord16be
       s <- getByteString (fromIntegral l)
       return (Authenticate s)

putTorCell :: TorCell -> Put
putTorCell Padding =
  putStandardCell $
     putWord32be 0 -- Circuit ID
putTorCell (Create circ bstr) =
  putStandardCell $
    do putWord32be       circ
       putWord8          1
       putByteString bstr
putTorCell (Created circ bstr) =
  putStandardCell $
    do putWord32be       circ
       putWord8          2
       putByteString bstr
putTorCell (Relay circ bstr) =
  putStandardCell $
    do putWord32be       circ
       putWord8          3
       putByteString bstr
putTorCell (Destroy circ dreason) =
  putStandardCell $
    do putWord32be       circ
       putWord8          4
       putDestroyReason  dreason
putTorCell (CreateFast circ keymat) =
  putStandardCell $
    do putWord32be       circ
       putWord8          5
       putByteString keymat
putTorCell (CreatedFast circ keymat deriv) =
  putStandardCell $
    do putWord32be       circ
       putWord8          6
       putByteString keymat
       putByteString deriv
putTorCell (NetInfo ttl oneside others) =
  putStandardCell $
    do putWord32be       0
       putWord8          8
       putWord32be       ttl
       putTorAddress     oneside
       putWord8          (fromIntegral (length others))
       forM_ others putTorAddress
putTorCell (RelayEarly circ bstr) =
  putStandardCell $
    do putWord32be       circ
       putWord8          9
       putByteString bstr
putTorCell (Create2 circ htype cdata) =
  putStandardCell $
    do putWord32be       circ
       putWord8          10
       putHandshakeType  htype
       putWord16be       (fromIntegral (BS.length cdata))
       putByteString cdata
putTorCell (Created2 circ cdata) =
  putStandardCell $
    do putWord32be       circ
       putWord8          11
       putWord16be       (fromIntegral (BS.length cdata))
       putByteString cdata
putTorCell (VPadding bstr) =
  do putWord32be       0
     putWord8          128
     putWord16be       (fromIntegral (BS.length bstr))
     putByteString bstr
putTorCell (Certs cs) =
  do putWord32be       0
     putWord8          129
     putLenByteString $
       do putWord8          (fromIntegral (length cs))
          forM_ cs putTorCert
putTorCell (AuthChallenge challenge methods) =
  do putWord32be       0
     putWord8          130
     putLenByteString $
       do putByteString challenge
          putWord16be       (fromIntegral (length methods))
          forM_ methods putWord16be
putTorCell (Authenticate authent) =
  do putWord32be       0
     putWord8          131
     putLenByteString $
       do putWord16be       1
          putWord16be       (fromIntegral (BS.length authent))
          putByteString authent
putTorCell (Authorize) =
  do putWord32be       0
     putWord8          132
     putWord16be       0
putTorCell (Versions) =
  do putWord16be       0
     putWord8          7
     putWord16be       2
     putWord16be       4

putLenByteString :: Put -> Put
putLenByteString m =
  do let bstr = runPut m
     putWord16be (fromIntegral (BSL.length bstr))
     putLazyByteString bstr

putStandardCell :: Put -> Put
putStandardCell m =
  do let bstr = runPut m
         infstr = bstr `BSL.append` BSL.repeat 0
     putLazyByteString (BSL.take 514 infstr)

-- -----------------------------------------------------------------------------

data DestroyReason = NoReason
                   | TorProtocolViolation
                   | InternalError
                   | RequestedDestroy
                   | NodeHibernating
                   | HitResourceLimit
                   | ConnectionFailed
                   | ORIdentityIssue
                   | ORConnectionClosed
                   | Finished
                   | CircuitConstructionTimeout
                   | CircuitDestroyed
                   | NoSuchService
                   | UnknownDestroyReason Word8
 deriving (Eq, Show, Typeable)

instance Exception DestroyReason

getDestroyReason :: Get DestroyReason
getDestroyReason =
  do b <- getWord8
     case b of
       0  -> return NoReason
       1  -> return TorProtocolViolation
       2  -> return InternalError
       3  -> return RequestedDestroy
       4  -> return NodeHibernating
       5  -> return HitResourceLimit
       6  -> return ConnectionFailed
       7  -> return ORIdentityIssue
       8  -> return ORConnectionClosed
       9  -> return Finished
       10 -> return CircuitConstructionTimeout
       11 -> return CircuitDestroyed
       12 -> return NoSuchService
       _  -> return (UnknownDestroyReason b)

putDestroyReason :: DestroyReason -> Put
putDestroyReason NoReason                   = putWord8 0
putDestroyReason TorProtocolViolation       = putWord8 1
putDestroyReason InternalError              = putWord8 2
putDestroyReason RequestedDestroy           = putWord8 3
putDestroyReason NodeHibernating            = putWord8 4
putDestroyReason HitResourceLimit           = putWord8 5
putDestroyReason ConnectionFailed           = putWord8 6
putDestroyReason ORIdentityIssue            = putWord8 7
putDestroyReason ORConnectionClosed         = putWord8 8
putDestroyReason Finished                   = putWord8 9
putDestroyReason CircuitConstructionTimeout = putWord8 10
putDestroyReason CircuitDestroyed           = putWord8 11
putDestroyReason NoSuchService              = putWord8 12
putDestroyReason (UnknownDestroyReason x)   = putWord8 x

-- -----------------------------------------------------------------------------

data HandshakeType = TAP | Reserved | NTor | Unknown Word16
 deriving (Eq, Show)

getHandshakeType :: Get HandshakeType
getHandshakeType =
  do t <- getWord16be
     case t of
       0x0000 -> return TAP
       0x0001 -> return Reserved
       0x0002 -> return NTor
       _      -> return (Unknown t)

putHandshakeType :: HandshakeType -> Put
putHandshakeType TAP         = putWord16be 0x0000
putHandshakeType Reserved    = putWord16be 0x0001
putHandshakeType NTor        = putWord16be 0x0002
putHandshakeType (Unknown x) = putWord16be x

-- -----------------------------------------------------------------------------

data TorCert = LinkKeyCert SignedCertificate
             | RSA1024Identity SignedCertificate
             | RSA1024Auth SignedCertificate
             | UnknownCertType Word8 ByteString
 deriving (Eq, Show)

getTorCert :: Get TorCert
getTorCert =
  do t <- getWord8
     l <- getWord16be
     c <- getByteString (fromIntegral l)
     case t of
       1 -> return (maybeBuild LinkKeyCert         t c)
       2 -> return (maybeBuild RSA1024Identity     t c)
       3 -> return (maybeBuild RSA1024Auth t c)
       _ -> return (UnknownCertType t c)
 where
  maybeBuild builder t bstr =
    case decodeSignedObject bstr of
      Left  _   -> UnknownCertType t bstr
      Right res -> builder res

putTorCert :: TorCert -> Put
putTorCert tc =
  do let (t, bstr) = case tc of
                       LinkKeyCert sc        -> (1, encodeSignedObject sc)
                       RSA1024Identity sc    -> (2, encodeSignedObject sc)
                       RSA1024Auth sc        -> (3, encodeSignedObject sc)
                       UnknownCertType ct bs -> (ct, bs)
     putWord8          t
     putWord16be       (fromIntegral (BS.length bstr))
     putByteString bstr

-- -----------------------------------------------------------------------------

getCerts :: Word16 -> Get TorCell
getCerts _ =
  do num   <- getWord8
     certs <- replicateM (fromIntegral num) getTorCert
     return (Certs certs)

