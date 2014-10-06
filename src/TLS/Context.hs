{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveDataTypeable #-}
module TLS.Context(
         IOSystem(..)
       , TLSContext
       , initialContext
       , startRecording
       , endRecording
       , emitRecording
       , setNextCipherSuite
       , nextHandshakeRecord
       , maybeGetHandshake
       , writeHandshake
       , sendChangeCipherSpec
       , receiveChangeCipherSpec
       , readTLS
       , writeTLS
       --
       , setTLSSecrets
       , setServerCertificates
       , getClientRandom
       , getServerRandom
       , getMasterSecret
       , getServerCertificates
       )
 where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Exception
import Control.Monad
import Crypto.Random
import Crypto.Random.DRBG
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Tagged
import Data.Typeable
import Data.Word
import Data.X509
import System.Entropy
import TLS.Alert
import TLS.Certificate
import TLS.ChangeCipher
import TLS.CipherSuite.Encryptor
import TLS.CipherSuite.Null
import TLS.CipherSuite.Stream
import TLS.CompressionMethod
import TLS.Handshake
import TLS.Handshake.Type
import TLS.ProtocolVersion
import TLS.Random
import TLS.Records.ContentType

data TLSError = TLSCiphertextTooLong
              | TLSNotHandshake
              | TLSNotChangeCipher
              | TLSNotAppData
              | TLSWrongHandshakeRecord
              | InternalErrorDoubleSave
              | TLSGenError GenError
              | TLSAlert Alert
              | TLSRecordError String
              | TLSEncodeDecodeError TLSEncryptionError
 deriving (Show, Typeable)

instance Exception TLSError

data IOSystem = IOSystem {
    ioRead  :: Int        -> IO ByteString
  , ioWrite :: ByteString -> IO ()
  , ioFlush :: IO ()
  }

type RNG = GenAutoReseed CtrDRBG HashDRBG

data TLSContext = TLSContext {
    readBS             :: Int -> IO ByteString
  , writeBS            :: ByteString -> IO ()
  , flushChannel       :: IO ()
  , curVersion         :: ProtocolVersion
    --
  , incomingTools      :: MVar ([Record], Compressor, Encryptor, Word64)
  , outgoingTools      :: MVar (RNG,      Compressor, Encryptor, Word64)
  , recordingInfo      :: MVar (Bool, ByteString)
    --
  , pendingCipherSuite :: MVar (Compressor, Encryptor)
  , clientRandom       :: MVar ByteString
  , serverRandom       :: MVar ByteString
  , masterSecret       :: MVar ByteString
  , serverCerts        :: MVar [SignedCertificate]
  }

-- ----------------------------------------------------------------------------

initialContext :: IOSystem -> IO TLSContext
initialContext iosys =
  do let taggedSeedLen = genSeedLength :: Tagged RNG ByteLength
         seedLen       = unTagged taggedSeedLen
     seed <- getEntropy seedLen
     let g = throwLeft (newGen seed)
     itMV <- newMVar ([], getCompressor nullCompression, nullEncryptor, 0)
     otMV <- newMVar (g,  getCompressor nullCompression, nullEncryptor, 0)
     riMV <- newMVar (False, error "Touched recording before start.")
     pnMV <- newMVar (error "No pending compressor",
                      error "No pending encryptor")
     crMV <- newMVar BS.empty
     srMV <- newMVar BS.empty
     msMV <- newMVar BS.empty
     scMV <- newMVar []
     return TLSContext {
       readBS = ioRead iosys
     , writeBS = ioWrite iosys
     , flushChannel = ioFlush iosys
     , curVersion = versionTLS1_2
     , incomingTools = itMV
     , outgoingTools = otMV
     , recordingInfo = riMV
     , pendingCipherSuite = pnMV
     , clientRandom = crMV
     , serverRandom = srMV
     , masterSecret = msMV
     , serverCerts = scMV
     }
 where
  nullEncryptor = buildStreamEncryptor nullHash NullKey BS.empty BS.empty
                                       BS.empty BS.empty BS.empty BS.empty

-- ----------------------------------------------------------------------------

startRecording :: TLSContext -> IO ()
startRecording c = modifyMVar_ (recordingInfo c) (constM (True, BS.empty))

emitRecording :: TLSContext -> IO ByteString
emitRecording c = snd <$> readMVar (recordingInfo c)

endRecording :: TLSContext -> IO ()
endRecording c =
  modifyMVar_ (recordingInfo c) (constM (False, error "not recording!"))

setNextCipherSuite :: TLSContext -> Compressor -> Encryptor -> IO ()
setNextCipherSuite c comp enc =
  modifyMVar_ (pendingCipherSuite c) $ constM (comp, enc)

-- ----------------------------------------------------------------------------

nextRecord :: TLSContext -> IO Record
nextRecord c =
  do it <- takeMVar (incomingTools c)
     case it of
       ([], cm, en, sq) ->
        do (f, it') <- getFreshRecords c cm en sq
           putMVar (incomingTools c) it'
           return f
       ((f:rest), cm, en, sq) ->
         do putMVar (incomingTools c) (rest, cm, en, sq)
            return f

nextHandshakeRecord :: IsHandshake a b =>
                       TLSContext -> b ->
                       IO a
nextHandshakeRecord c ctxt =
  do rec <- nextRecord c
     case rec of
       RecordChangeCipher _ ->
         do flipIncomingCipherSuite c
            nextHandshakeRecord c ctxt
       RecordAppData _ ->
         throwIO TLSNotHandshake
       RecordAlert a ->
         throwIO (TLSAlert a)
       RecordHandshake raw ->
         case decodeHandshake ctxt raw of
           Left err ->
             do (rs, cm, en, sq) <- takeMVar (incomingTools c)
                putMVar (incomingTools c) (rec : rs, cm, en, sq)
                throwIO (TLSRecordError err)
           Right x ->
             return x

maybeGetHandshake :: IsHandshake a b =>
                     TLSContext -> b ->
                     IO (Maybe a)
maybeGetHandshake tls ctxt =
  catch (Just <$> nextHandshakeRecord tls ctxt)
        (\ (_ :: SomeException) -> return Nothing)

receiveChangeCipherSpec :: TLSContext -> IO ()
receiveChangeCipherSpec c =
  do rec <- nextRecord c
     case rec of
       RecordChangeCipher _ ->
         flipIncomingCipherSuite c
       RecordAppData _ ->
         throw TLSNotChangeCipher
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake _ ->
         throw TLSNotChangeCipher

readTLS :: TLSContext -> IO ByteString
readTLS c =
  do rec <- nextRecord c
     case rec of
       RecordChangeCipher _ ->
         do flipIncomingCipherSuite c
            readTLS c
       RecordAppData bstr ->
         return bstr
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake _ ->
         throw TLSNotAppData

-- ----------------------------------------------------------------------------

writeRecord :: TLSContext -> Record -> IO ()
writeRecord c r =
  do (g, ocomp, oenc, seqNum) <- takeMVar (outgoingTools c)
     let recordBS        = runPut (putRecord r)
         plains          = fragmentMessage recordBS
         (comps, ocomp') = compressRecords ocomp plains
         rType           = recordType r
         ver             = curVersion c
     (encs, oenc', g', seqNum') <- encryptRecords oenc g seqNum rType ver comps
     let rawmsgs = map (encodeCipher rType ver) encs
     modifyMVar_ (recordingInfo c) $ \ x ->
       case x of
         (True, bstr)
           | isHandshake r -> return (True, bstr `BS.append` recordBS)
           | otherwise     -> return x
         _            -> return x
     forM_ rawmsgs (writeBS c)
     flushChannel c
     if rType == TypeChangeCipherSpec
        then do (ocomp'', oenc'') <- readMVar (pendingCipherSuite c)
                putMVar (outgoingTools c) (g', ocomp'', oenc'', 0)
        else putMVar (outgoingTools c) (g', ocomp', oenc', seqNum')

fragmentMessage :: ByteString -> [ByteString]
fragmentMessage bstr
  | BS.length bstr <= 16384 = [bstr]
  | otherwise               =
     let (f, rest) = BS.splitAt 16384 bstr
     in f : fragmentMessage rest

compressRecords :: Compressor -> [ByteString] -> ([ByteString], Compressor)
compressRecords s []       = ([], s)
compressRecords s (f:rest) =
  let (f', s') = runCompress s f
      (rest', s'') = compressRecords s' rest
  in ((f' : rest'), s'')

encryptRecords :: CryptoRandomGen g =>
                  Encryptor -> g -> Word64 -> ContentType -> ProtocolVersion ->
                  [ByteString] ->
                  IO ([ByteString], Encryptor, g, Word64)
encryptRecords s g n _ _ []       =
  return ([], s, g, n)
encryptRecords s g n ct pv (f:rest) =
  case runEncrypt s g n ct pv f of
    Left e ->
      throw (TLSEncodeDecodeError e)
    Right (f', s', g') ->
      do (rest', s'', g'', n') <- encryptRecords s' g' (n + 1) ct pv rest
         return ((f' : rest'), s'', g'', n')

encodeCipher :: ContentType -> ProtocolVersion -> ByteString -> ByteString
encodeCipher ct pv bstr = runPut $
  do putContentType ct
     putProtocolVersion pv
     putWord16be (fromIntegral (BS.length bstr))
     putLazyByteString bstr

-- ----------------------------------------------------------------------------

writeHandshake :: IsHandshake a b =>
                  TLSContext -> a ->
                  IO ()
writeHandshake c hs = writeRecord c (RecordHandshake (encodeHandshake hs))

sendChangeCipherSpec :: TLSContext -> IO ()
sendChangeCipherSpec c = writeRecord c (RecordChangeCipher ChangeCipherSpec)

writeTLS :: TLSContext -> ByteString -> IO ()
writeTLS c bstr = writeRecord c (RecordAppData bstr)

-- ----------------------------------------------------------------------------

setTLSSecrets :: TLSContext -> Random -> Random -> ByteString -> IO ()
setTLSSecrets c cr sr ms =
  do modifyMVar_ (clientRandom c) (constM (runPut (putRandom cr)))
     modifyMVar_ (serverRandom c) (constM (runPut (putRandom sr)))
     modifyMVar_ (masterSecret c) (constM ms)

setServerCertificates :: TLSContext -> Maybe [ASN1Cert] -> IO ()
setServerCertificates c mcerts =
  case mcerts of
    Nothing -> modifyMVar_ (serverCerts c) (constM [])
    Just xs -> modifyMVar_ (serverCerts c) (constM (map unASN1Cert xs))
 where unASN1Cert (ASN1Cert x) = x

getClientRandom :: TLSContext -> IO ByteString
getClientRandom = readMVar . clientRandom

getServerRandom :: TLSContext -> IO ByteString
getServerRandom = readMVar . serverRandom

getMasterSecret :: TLSContext -> IO ByteString
getMasterSecret = readMVar . masterSecret

getServerCertificates :: TLSContext -> IO [SignedCertificate]
getServerCertificates = readMVar . serverCerts

-- ----------------------------------------------------------------------------

flipIncomingCipherSuite :: TLSContext -> IO ()
flipIncomingCipherSuite c =
  do (rs, _, _, _) <- takeMVar (incomingTools c)
     (cm, en)      <- readMVar (pendingCipherSuite c)
     putMVar (incomingTools c) (rs, cm, en, 0)

-- ----------------------------------------------------------------------------

getFreshRecords :: TLSContext -> Compressor -> Encryptor -> Word64 ->
                   IO (Record, ([Record], Compressor, Encryptor, Word64))
getFreshRecords c icomp ienc seqNum =
  do (conType, pver, len) <- runGet readHeader <$> readBS c (1 + 2 + 2)
     when (len > 18432) $ throw TLSCiphertextTooLong -- 18432 == 2^14 + 2048
     pkt <- readBS c (fromIntegral len)
     case runDecrypt ienc seqNum conType pver pkt of
       Left err ->
         throw (TLSEncodeDecodeError err)
       Right (compr, ienc') ->
         do let (ptext, icomp') = runDecompress icomp compr
            (frec:rrecs) <- readRecords (typeParser conType) ptext
            let seqNum' = seqNum + 1
            modifyMVar_ (recordingInfo c) $ \ x ->
              case x of
                (True, bstr)
                  | conType == TypeHandshake ->
                      return (True, bstr `BS.append` ptext)
                  | otherwise ->
                      return x
                _            -> return x
            return (frec, (rrecs, icomp', ienc', seqNum'))

readRecords :: Get Record -> ByteString -> IO [Record]
readRecords getter bstr
  | BS.null bstr = return []
  | otherwise    =
     case runGetOrFail getter bstr of
       Left  (_, _, err)  -> throw (TLSRecordError err)
       Right (rest, _, x) -> (x :) <$> readRecords getter rest

typeParser :: ContentType -> Get Record
typeParser TypeChangeCipherSpec = RecordChangeCipher <$> getChangeCipherSpec
typeParser TypeAlert            = RecordAlert <$> getAlert
typeParser TypeHandshake        = RecordHandshake <$> getRawHandshake
typeParser TypeApplicationData  = RecordAppData <$> getRemainingLazyByteString

readHeader :: Get (ContentType, ProtocolVersion, Word16)
readHeader =
  do ct <- getContentType
     pv <- getProtocolVersion
     ln <- getWord16be
     return (ct, pv, ln)

-- ----------------------------------------------------------------------------

data Record = RecordChangeCipher ChangeCipherSpec
            | RecordAlert        Alert
            | RecordHandshake    RawHandshake
            | RecordAppData      ByteString
 deriving (Eq, Show)

putRecord :: Record -> Put
putRecord (RecordChangeCipher x) = putChangeCipherSpec x
putRecord (RecordAlert        x) = putAlert x
putRecord (RecordHandshake    x) = putRawHandshake x
putRecord (RecordAppData      x) = putLazyByteString x

recordType :: Record -> ContentType
recordType (RecordChangeCipher _) = TypeChangeCipherSpec
recordType (RecordAlert        _) = TypeAlert
recordType (RecordHandshake    _) = TypeHandshake
recordType (RecordAppData      _) = TypeApplicationData

isHandshake :: Record -> Bool
isHandshake (RecordHandshake _) = True
isHandshake _                   = False

constM :: a -> b -> IO a
constM x _ = return x
