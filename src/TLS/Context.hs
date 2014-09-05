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

newtype TLSContext = TLS (MVar TLSState)

data TLSState = TLSState {
    readBS             :: Int -> IO ByteString
  , writeBS            :: ByteString -> IO ()
  , flushChannel       :: IO ()
  , randomGen          :: RNG
    --
  , incomingCompressor :: Compressor
  , outgoingCompressor :: Compressor
  , incomingEncryptor  :: Encryptor
  , outgoingEncryptor  :: Encryptor
  , pendingCipherSuite :: (Compressor, Encryptor)
    --
  , clientRandom       :: ByteString
  , serverRandom       :: ByteString
  , masterSecret       :: ByteString
  , serverCerts        :: [SignedCertificate]
    --
  , curVersion         :: ProtocolVersion
  , savedRecords       :: [Record]
    --
  , amRecording        :: Bool
  , recording          :: ByteString
    --
  , incomingSeq        :: Word64
  , outgoingSeq        :: Word64
  }

-- ----------------------------------------------------------------------------

initialContext :: IOSystem -> IO TLSContext
initialContext iosys =
  do let taggedSeedLen = genSeedLength :: Tagged RNG ByteLength
         seedLen       = unTagged taggedSeedLen
     seed <- getEntropy seedLen
     case newGen seed of
       Left  err -> throwIO err
       Right g   -> TLS <$> newMVar (initialState g)
 where
  initialState g = TLSState {
    readBS             = ioRead iosys
  , writeBS            = ioWrite iosys
  , flushChannel       = ioFlush iosys
  , randomGen          = g
  , incomingCompressor = getCompressor nullCompression
  , outgoingCompressor = getCompressor nullCompression
  , incomingEncryptor  = nullEncryptor
  , outgoingEncryptor  = nullEncryptor
  , clientRandom       = BS.empty
  , serverRandom       = BS.empty
  , masterSecret       = BS.empty
  , serverCerts        = []
  , pendingCipherSuite = (error "No pending compressor set!",
                          error "No pending encryptor set!")
  , curVersion         = versionTLS1_2
  , savedRecords       = []
  , recording          = error "touched recording before starting?"
  , amRecording        = False
  , incomingSeq        = 0
  , outgoingSeq        = 0
  }
  nullEncryptor = buildStreamEncryptor nullHash NullKey BS.empty BS.empty
                                       BS.empty BS.empty BS.empty BS.empty

-- ----------------------------------------------------------------------------

startRecording :: TLSContext -> IO ()
startRecording (TLS cMV) =
  do c <- takeMVar cMV
     putMVar cMV $! c{ amRecording = True, recording = BS.empty }

emitRecording :: TLSContext -> IO ByteString
emitRecording (TLS cMV) = recording <$> readMVar cMV

endRecording :: TLSContext -> IO ()
endRecording (TLS cMV) =
  do c <- takeMVar cMV
     putMVar cMV $! c{amRecording = False, recording = error "not recording!"}

setNextCipherSuite :: TLSContext -> Compressor -> Encryptor -> IO ()
setNextCipherSuite (TLS cMV) comp enc =
  do c <- takeMVar cMV
     putMVar cMV $! c{ pendingCipherSuite = (comp, enc) }

-- ----------------------------------------------------------------------------

nextRecord :: TLSContext -> IO Record
nextRecord (TLS cMV) =
  do c <- takeMVar cMV
     (c', rec) <- forceNext c
     putMVar cMV c'
     return rec
 where
  forceNext c =
    case savedRecords c of
      []       -> forceNext =<< getFreshRecords c
      (r:rest) -> return (c{ savedRecords = rest }, r)

nextHandshakeRecord :: IsHandshake a b =>
                       TLSContext -> b ->
                       IO a
nextHandshakeRecord tls@(TLS cMV) ctxt =
  do rec <- nextRecord tls
     case rec of
       RecordChangeCipher _ ->
         do c <- takeMVar cMV
            putMVar cMV $! flipIncomingCipherSuite c
            nextHandshakeRecord tls ctxt
       RecordAppData _ ->
         throwIO TLSNotHandshake
       RecordAlert a ->
         throwIO (TLSAlert a)
       RecordHandshake raw ->
         case decodeHandshake ctxt raw of
           Left err ->
             do c <- takeMVar cMV
                putMVar cMV $! c{ savedRecords = savedRecords c ++ [rec] }
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
receiveChangeCipherSpec tls@(TLS cMV) =
  do rec <- nextRecord tls
     case rec of
       RecordChangeCipher _ ->
         do c <- takeMVar cMV
            putMVar cMV $! flipIncomingCipherSuite c
       RecordAppData _ ->
         throw TLSNotChangeCipher
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake _ ->
         throw TLSNotChangeCipher

readTLS :: TLSContext -> IO ByteString
readTLS tls@(TLS cMV) =
  do rec <- nextRecord tls
     case rec of
       RecordChangeCipher _ ->
         do c <- takeMVar cMV
            putMVar cMV $! flipIncomingCipherSuite c
            readTLS tls
       RecordAppData bstr ->
         return bstr
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake _ ->
         throw TLSNotAppData

-- ----------------------------------------------------------------------------

writeRecord :: TLSContext -> Record -> IO ()
writeRecord (TLS cMV) r =
  do c <- takeMVar cMV
     let recordBS     = runPut (putRecord r)
         recording'   = if amRecording c && isHandshake r
                          then recording c `BS.append` recordBS
                          else recording c
         plains       = fragmentMessage recordBS
         (comps, oc') = compressRecords (outgoingCompressor c) plains
         recType      = recordType r
     (encs, oe', g', n') <- encryptRecords (outgoingEncryptor c)
                                           (randomGen c)
                                           (outgoingSeq c)
                                           recType
                                           (curVersion c)
                                           comps
     let rawmsgs = map (encodeCipher recType (curVersion c)) encs
     writeBS c (BS.concat rawmsgs)
     flushChannel c
     let c' = if recType == TypeChangeCipherSpec
                then flipOutgoingCipherSuite c
                else c{ outgoingCompressor = oc'
                      , outgoingEncryptor  = oe'
                      , outgoingSeq        = n' }
     putMVar cMV $! c'{ randomGen = g', recording = recording' }

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
setTLSSecrets (TLS c) cr sr ms =
  do s <- takeMVar c
     putMVar c $ s{ clientRandom = runPut (putRandom cr)
                  , serverRandom = runPut (putRandom sr)
                  , masterSecret = ms }

setServerCertificates :: TLSContext -> Maybe [ASN1Cert] -> IO ()
setServerCertificates (TLS c) mcerts =
  do s <- takeMVar c
     case mcerts of
       Nothing -> putMVar c $ s{ serverCerts = [] }
       Just xs -> putMVar c $ s{ serverCerts = map unASN1Cert xs }
 where unASN1Cert (ASN1Cert x) = x

getClientRandom :: TLSContext -> IO ByteString
getClientRandom (TLS c) = clientRandom <$> readMVar c

getServerRandom :: TLSContext -> IO ByteString
getServerRandom (TLS c) = serverRandom <$> readMVar c

getMasterSecret :: TLSContext -> IO ByteString
getMasterSecret (TLS c) = masterSecret <$> readMVar c

getServerCertificates :: TLSContext -> IO [SignedCertificate]
getServerCertificates (TLS c) = serverCerts <$> readMVar c

-- ----------------------------------------------------------------------------

flipIncomingCipherSuite :: TLSState -> TLSState
flipIncomingCipherSuite c@TLSState{ pendingCipherSuite = (comp, enc) } =
  c{ incomingCompressor = comp, incomingEncryptor = enc, incomingSeq = 0 }

flipOutgoingCipherSuite :: TLSState -> TLSState
flipOutgoingCipherSuite c@TLSState{ pendingCipherSuite = (comp, enc) } =
  c{ outgoingCompressor = comp, outgoingEncryptor = enc, outgoingSeq = 0 }

-- ----------------------------------------------------------------------------

getFreshRecords :: TLSState -> IO TLSState
getFreshRecords c =
  do (conType, pver, len) <- runGet readHeader <$> readBS c (1 + 2 + 2)
     when (len > 18432) $ throw TLSCiphertextTooLong -- 18432 == 2^14 + 2048
     pkt <- readBS c (fromIntegral len)
     case runDecrypt (incomingEncryptor c) (incomingSeq c) conType pver pkt of
       Left err ->
         throw (TLSEncodeDecodeError err)
       Right (compr, e') ->
         do let (ptext, c') = runDecompress (incomingCompressor c) compr
            records <- readRecords (typeParser conType) ptext
            let newRecord = recording c `BS.append` ptext
                shouldRecord = amRecording c && (conType == TypeHandshake)
                recording' = if shouldRecord then newRecord else recording c
            return c{ incomingEncryptor = e', incomingCompressor = c'
                    , incomingSeq = incomingSeq c + 1, recording = recording'
                    , savedRecords = savedRecords c ++ records }

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

