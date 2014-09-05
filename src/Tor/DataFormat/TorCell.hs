module Tor.DataFormat.TorCell(
         TorCell(..),       putTorCell,       getTorCell
       , RelayCommand(..),  putRelayCommand,  getRelayCommand
       , DestroyReason(..), putDestroyReason, getDestroyReason
       , TorAddress(..),    putTorAddress,    getTorAddress
       , HandshakeType(..), putHandshakeType, getHandshakeType
       , TorCert(..),       putTorCert,       getTorCert
       , unTorAddress
       )
 where

import Control.Applicative
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import Data.ByteString.Lazy.Char8(pack,unpack)
import qualified Data.ByteString.Lazy as BS
import Data.List(intercalate)
import Data.X509
import Data.Word
import Numeric

data TorCell = Padding
             | Create      Word32 ByteString
             | Created     Word32 ByteString
             | Relay       Word32 RelayCommand Word16 Word16 Word32 ByteString
             | Destroy     Word32 DestroyReason
             | CreateFast  Word32 ByteString
             | CreatedFast Word32 ByteString ByteString
             | NetInfo            Word32 TorAddress [TorAddress]
             | RelayEarly  Word32
             | Create2     Word32 HandshakeType ByteString
             | Created2    Word32 ByteString
             | Versions
             | VPadding           ByteString
             | Certs              [TorCert]
             | AuthChallenge      ByteString [Word16]
             | Authenticate       ByteString
             | Authorize
 deriving (Eq, Show)

getTorCell :: Get TorCell
getTorCell =
  do circuit <- getWord32be
     command <- getWord8
     case command of
       0   -> return Padding
       1   -> Create circuit <$> getLazyByteString (128 + 16 + 42)
       2   -> Created circuit <$> getLazyByteString (128 + 20)
       3   -> do cmd <- getRelayCommand
                 rec <- getWord16be
                 str <- getWord16be
                 dig <- getWord32be
                 len <- getWord16be
                 pay <- getLazyByteString (509 - 11)
                 let pay' = BS.take (fromIntegral len) pay
                 return (Relay circuit cmd rec str dig pay')
       4   -> Destroy circuit <$> getDestroyReason
       5   -> CreateFast circuit <$> getLazyByteString 20
       6   -> CreatedFast circuit <$> getLazyByteString 20
                                  <*> getLazyByteString 20
       8   -> do tstamp   <- getWord32be
                 otherOR  <- getTorAddress
                 numAddrs <- getWord8
                 thisOR   <- replicateM (fromIntegral numAddrs) getTorAddress
                 return (NetInfo tstamp otherOR thisOR)
       9   -> return (RelayEarly circuit)
       10  -> do htype <- getHandshakeType
                 hlen  <- getWord16be
                 hdata <- getLazyByteString (fromIntegral hlen)
                 return (Create2 circuit htype hdata)
       11  -> do hlen  <- getWord16be
                 hdata <- getLazyByteString (fromIntegral hlen)
                 return (Created2 circuit hdata)
       7   -> fail "Should not be getting versions through this interface."
       128 -> getVariableLength "VPadding"      getVPadding
       129 -> getVariableLength "Certs"         getCerts
       130 -> getVariableLength "AuthChallenge" getAuthChallenge
       131 -> getVariableLength "Authenticate"  getAuthenticate
       132 -> getVariableLength "Authorize"     (return Authorize)
       _   -> fail "Improper Tor cell command."
 where
  getVariableLength name getter =
    do len   <- getWord16be
       body  <- getLazyByteString (fromIntegral len)
       case runGetOrFail getter body of
         Left  (_, _, s) -> fail ("Couldn't read " ++ name ++ " body: " ++ s)
         Right (_, _, x) -> return x
  --
  getVPadding = VPadding <$> getRemainingLazyByteString
  --
  getAuthChallenge =
    do challenge <- getLazyByteString 32
       n_methods <- getWord16be
       methods   <- replicateM (fromIntegral n_methods) getWord16be
       return (AuthChallenge challenge methods)
  --
  getAuthenticate =
    do _ <- getWord16be -- AuthType
       l <- getWord16be
       s <- getLazyByteString (fromIntegral l)
       return (Authenticate s)

putTorCell :: TorCell -> Put
putTorCell Padding =
  do putWord32be 0 -- Circuit ID
     putWord8    0 -- PADDING
putTorCell (Create circ bstr) =
  do putWord32be       circ
     putWord8          1
     putLazyByteString bstr
putTorCell (Created circ bstr) =
  do putWord32be       circ
     putWord8          2
     putLazyByteString bstr
putTorCell (Relay circ cmd rec sid dig rdata) =
  do putWord32be       circ
     putWord8          3
     putRelayCommand   cmd
     putWord16be       rec
     putWord16be       sid
     putWord32be       dig
     putWord16be       (fromIntegral (BS.length rdata) + 11)
     putLazyByteString rdata
putTorCell (Destroy circ dreason) =
  do putWord32be       circ
     putWord8          4
     putDestroyReason  dreason
putTorCell (CreateFast circ keymat) =
  do putWord32be       circ
     putWord8          5
     putLazyByteString keymat
putTorCell (CreatedFast circ keymat deriv) =
  do putWord32be       circ
     putWord8          6
     putLazyByteString keymat
     putLazyByteString deriv
putTorCell (NetInfo ttl oneside others) =
  do putWord32be       0
     putWord8          8
     putWord32be       ttl
     putTorAddress     oneside
     putWord8          (fromIntegral (length others))
     forM_ others putTorAddress
putTorCell (RelayEarly circ) =
  do putWord32be       circ
     putWord8          9
putTorCell (Create2 circ htype cdata) =
  do putWord32be       circ
     putWord8          10
     putHandshakeType  htype
     putWord16be       (fromIntegral (BS.length cdata))
     putLazyByteString cdata
putTorCell (Created2 circ cdata) =
  do putWord32be       circ
     putWord8          11
     putWord16be       (fromIntegral (BS.length cdata))
     putLazyByteString cdata
putTorCell (VPadding bstr) =
  do putWord32be       0
     putWord8          128
     putWord16be       (fromIntegral (BS.length bstr))
     putLazyByteString bstr
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
       do putLazyByteString challenge
          putWord16be       (fromIntegral (length methods))
          forM_ methods putWord16be
putTorCell (Authenticate authent) =
  do putWord32be       0
     putWord8          131
     putLenByteString $
       do putWord16be       1
          putWord16be       (fromIntegral (BS.length authent))
          putLazyByteString authent
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
     putWord16be (fromIntegral (BS.length bstr))
     putLazyByteString bstr

-- -----------------------------------------------------------------------------

data RelayCommand = RelayBegin
                  | RelayData
                  | RelayEnd
                  | RelayConnected
                  | RelaySendMe
                  | RelayExtend
                  | RelayExtended
                  | RelayTruncate
                  | RelayTruncated
                  | RelayDrop
                  | RelayResolve
                  | RelayResolved
                  | RelayBeginDir
                  | RelayExtend2
                  | RelayExtended2
                  | RelayEstablishIntro
                  | RelayEstablishRendezvous
                  | RelayIntroduce1
                  | RelayIntroduce2
                  | RelayRendezvous1
                  | RelayRendezvous2
                  | RelayIntroEstablished
                  | RelayRendezvousEstablished
                  | RelayIntroducedAck
                  | RelayCommandUnknown Word8
 deriving (Eq, Show)

getRelayCommand :: Get RelayCommand
getRelayCommand =
  do b <- getWord8
     case b of
       1  -> return RelayBegin
       2  -> return RelayData
       3  -> return RelayEnd
       4  -> return RelayConnected
       5  -> return RelaySendMe
       6  -> return RelayExtend
       7  -> return RelayExtended
       8  -> return RelayTruncate
       9  -> return RelayTruncated
       10 -> return RelayDrop
       11 -> return RelayResolve
       12 -> return RelayResolved
       13 -> return RelayBeginDir
       14 -> return RelayExtend2
       15 -> return RelayExtended2
       32 -> return RelayEstablishIntro
       33 -> return RelayEstablishRendezvous
       34 -> return RelayIntroduce1
       35 -> return RelayIntroduce2
       36 -> return RelayRendezvous1
       37 -> return RelayRendezvous2
       38 -> return RelayIntroEstablished
       39 -> return RelayRendezvousEstablished
       40 -> return RelayIntroducedAck
       _  -> return (RelayCommandUnknown b)

putRelayCommand :: RelayCommand -> Put
putRelayCommand RelayBegin                  = putWord8 1
putRelayCommand RelayData                   = putWord8 2
putRelayCommand RelayEnd                    = putWord8 3
putRelayCommand RelayConnected              = putWord8 4
putRelayCommand RelaySendMe                 = putWord8 5
putRelayCommand RelayExtend                 = putWord8 6
putRelayCommand RelayExtended               = putWord8 7
putRelayCommand RelayTruncate               = putWord8 8
putRelayCommand RelayTruncated              = putWord8 9
putRelayCommand RelayDrop                   = putWord8 10
putRelayCommand RelayResolve                = putWord8 11
putRelayCommand RelayResolved               = putWord8 12
putRelayCommand RelayBeginDir               = putWord8 13
putRelayCommand RelayExtend2                = putWord8 14
putRelayCommand RelayExtended2              = putWord8 15
putRelayCommand RelayEstablishIntro         = putWord8 32
putRelayCommand RelayEstablishRendezvous    = putWord8 33
putRelayCommand RelayIntroduce1             = putWord8 34
putRelayCommand RelayIntroduce2             = putWord8 35
putRelayCommand RelayRendezvous1            = putWord8 36
putRelayCommand RelayRendezvous2            = putWord8 37
putRelayCommand RelayIntroEstablished       = putWord8 38
putRelayCommand RelayRendezvousEstablished  = putWord8 39
putRelayCommand RelayIntroducedAck          = putWord8 40
putRelayCommand (RelayCommandUnknown x)     = putWord8 x

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
 deriving (Eq, Show)

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

data TorAddress = Hostname String
                | IP4 String
                | IP6 String
                | TransientError String
                | NontransientError String
 deriving (Eq, Show)

unTorAddress :: TorAddress -> String
unTorAddress (Hostname s) = s
unTorAddress (IP4 s) = s
unTorAddress (IP6 s) = s
unTorAddress _       = error "unTorAddress: invalid input."

getTorAddress :: Get TorAddress
getTorAddress =
  do atype <- getWord8
     len   <- getWord8
     value <- getLazyByteString (fromIntegral len)
     case (atype, len) of
       (0x00, _)  -> return (Hostname (unpack value))
       (0x04, 4)  -> return (IP4 (ip4ToString value))
       (0x04, _)  -> return (TransientError "Bad length for IP4 address.")
       (0x06, 16) -> return (IP6 (ip6ToString value))
       (0x06, _)  -> return (TransientError "Bad length for IP6 address.")
       (0xF0, _)  -> return (TransientError "External transient error.")
       (0xF1, _)  -> return (NontransientError "External nontransient error.")
       (_,    _)  -> return (NontransientError ("Unknown address type: " ++ show atype))

ip4ToString :: ByteString -> String
ip4ToString bstr = intercalate "." (map show (BS.unpack bstr))

ip6ToString :: ByteString -> String
ip6ToString bstr = intercalate ":" (run (BS.unpack bstr))
 where
  run :: [Word8] -> [String]
  run []         = []
  run [_]        = ["ERROR"]
  run (a:b:rest) =
    let a' = fromIntegral a :: Word16
        b' = fromIntegral b :: Word16
        v  = (a' `shiftL` 8) .|. b'
    in (showHex v "" : run rest)

putTorAddress :: TorAddress -> Put
putTorAddress (Hostname str) =
  do putWord8 0x00
     let bstr = pack str
     putWord8 (fromIntegral (BS.length bstr))
     putLazyByteString bstr
putTorAddress (IP4 str) =
  do putWord8 0x04
     putWord8 4
     forM_ (unintercalate '.' str) (putWord8 . read)
putTorAddress (IP6 str) =
  do putWord8 0x06
     putWord8 16
     forM_ (unintercalate ':' str) $ \ v ->
       case readHex v of
        []        -> fail "Couldn't read IP6 address component."
        ((x,_):_) -> putWord16be x
putTorAddress (TransientError _) =
  do putWord8 0xF0
     putWord8 0
putTorAddress (NontransientError _) =
  do putWord8 0xF1
     putWord8 0

unintercalate :: Char -> String -> [String]
unintercalate _ "" = []
unintercalate c str =
  let (first, rest) = span (/= c) str
  in first : (unintercalate c (drop 1 rest))

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
             | RSA1024Authenticate SignedCertificate
             | UnknownCertType Word8 ByteString
 deriving (Eq, Show)

getTorCert :: Get TorCert
getTorCert =
  do t <- getWord8
     l <- getWord16be
     c <- getLazyByteString (fromIntegral l)
     case t of
       1 -> return (maybeBuild LinkKeyCert         t c)
       2 -> return (maybeBuild RSA1024Identity     t c)
       3 -> return (maybeBuild RSA1024Authenticate t c)
       _ -> return (UnknownCertType t c)
 where
  maybeBuild builder t bstr =
    case decodeSignedObject (BS.toStrict bstr) of
      Left  _   -> UnknownCertType t bstr
      Right res -> builder res

putTorCert :: TorCert -> Put
putTorCert tc =
  do let (t, bstr) = case tc of
                       LinkKeyCert sc         -> (1, encodeSignedObject' sc)
                       RSA1024Identity sc     -> (2, encodeSignedObject' sc)
                       RSA1024Authenticate sc -> (3, encodeSignedObject' sc)
                       UnknownCertType ct bs  -> (ct, bs)
     putWord8          t
     putWord16be       (fromIntegral (BS.length bstr))
     putLazyByteString bstr
 where encodeSignedObject' = BS.fromStrict . encodeSignedObject

-- -----------------------------------------------------------------------------

getCerts :: Get TorCell
getCerts =
  do num   <- getWord8
     certs <- replicateM (fromIntegral num) getTorCert
     return (Certs certs)
