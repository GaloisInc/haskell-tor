{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveDataTypeable #-}
module TLS.Context.Explicit(
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
       )
 where

import Control.Applicative
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
import System.Entropy
import TLS.Alert
import TLS.ChangeCipher
import TLS.CipherSuite.Encryptor
import TLS.CipherSuite.Null
import TLS.CipherSuite.Stream
import TLS.CompressionMethod
import TLS.Handshake
import TLS.Handshake.Type
import TLS.ProtocolVersion
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
  , randomGen          :: RNG
    --
  , incomingCompressor :: Compressor
  , outgoingCompressor :: Compressor
  , incomingEncryptor  :: Encryptor
  , outgoingEncryptor  :: Encryptor
  , pendingCipherSuite :: (Compressor, Encryptor)
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
       Left  err -> throw err
       Right g   -> return (initialState g)
 where
  initialState g = TLSContext {
    readBS             = ioRead iosys
  , writeBS            = ioWrite iosys
  , flushChannel       = ioFlush iosys
  , randomGen          = g
  , incomingCompressor = getCompressor nullCompression
  , outgoingCompressor = getCompressor nullCompression
  , incomingEncryptor  = nullEncryptor
  , outgoingEncryptor  = nullEncryptor
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

startRecording :: TLSContext -> TLSContext
startRecording c = c{ amRecording = True, recording = BS.empty }

emitRecording :: TLSContext -> ByteString
emitRecording c = recording c

endRecording :: TLSContext -> TLSContext
endRecording c = c{ amRecording = False, recording = error "not recording!" }

setNextCipherSuite :: TLSContext -> Compressor -> Encryptor -> TLSContext
setNextCipherSuite c comp enc = c{ pendingCipherSuite = (comp, enc) }

-- ----------------------------------------------------------------------------

nextRecord :: TLSContext -> IO (TLSContext, Record)
nextRecord c =
  case savedRecords c of
    []       -> nextRecord =<< getFreshRecords c
    (r:rest) -> return (c{savedRecords = rest }, r)

nextHandshakeRecord :: IsHandshake a b =>
                       TLSContext -> b ->
                       IO (TLSContext, a)
nextHandshakeRecord c ctxt =
  do (c', rec) <- nextRecord c
     case rec of
       RecordChangeCipher _ ->
         nextHandshakeRecord (flipIncomingCipherSuite c) ctxt
       RecordAppData _ ->
         throw TLSNotHandshake
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake raw ->
         case decodeHandshake ctxt raw of
           Left  err -> throw (TLSRecordError err)
           Right x   -> return (c', x)

maybeGetHandshake :: IsHandshake a b =>
                     TLSContext -> b ->
                     IO (TLSContext, Maybe a)
maybeGetHandshake c ctxt =
  catch (do (c', rec) <- nextHandshakeRecord c ctxt
            return (c', Just rec))
        (\ (_ :: SomeException) -> return (c, Nothing))

receiveChangeCipherSpec :: TLSContext -> IO TLSContext
receiveChangeCipherSpec c =
  do (c', rec) <- nextRecord c
     case rec of
       RecordChangeCipher _ ->
         return (flipIncomingCipherSuite c')
       RecordAppData _ ->
         throw TLSNotChangeCipher
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake _ ->
         throw TLSNotChangeCipher

readTLS :: TLSContext -> IO (TLSContext, ByteString)
readTLS c =
  do (c', rec) <- nextRecord c
     case rec of
       RecordChangeCipher _ ->
         readTLS (flipIncomingCipherSuite c)
       RecordAppData bstr ->
         return (c', bstr)
       RecordAlert a ->
         throw (TLSAlert a)
       RecordHandshake _ ->
         throw TLSNotAppData

-- ----------------------------------------------------------------------------

writeRecord :: TLSContext -> Record -> IO TLSContext
writeRecord c r =
  do let recordBS     = runPut (putRecord r)
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
     return c'{ randomGen = g', recording = recording' }

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
                  IO TLSContext
writeHandshake c hs = writeRecord c (RecordHandshake (encodeHandshake hs))

sendChangeCipherSpec :: TLSContext -> IO TLSContext
sendChangeCipherSpec c = writeRecord c (RecordChangeCipher ChangeCipherSpec)

writeTLS :: TLSContext -> ByteString -> IO TLSContext
writeTLS c bstr = writeRecord c (RecordAppData bstr)

-- ----------------------------------------------------------------------------

flipIncomingCipherSuite :: TLSContext -> TLSContext
flipIncomingCipherSuite c@TLSContext{ pendingCipherSuite = (comp, enc) } =
  c{ incomingCompressor = comp, incomingEncryptor = enc, incomingSeq = 0 }

flipOutgoingCipherSuite :: TLSContext -> TLSContext
flipOutgoingCipherSuite c@TLSContext{ pendingCipherSuite = (comp, enc) } =
  c{ outgoingCompressor = comp, outgoingEncryptor = enc, outgoingSeq = 0 }

-- ----------------------------------------------------------------------------

getFreshRecords :: TLSContext -> IO TLSContext
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

