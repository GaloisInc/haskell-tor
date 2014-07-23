module TLS.Context.Implicit(
         IOSystem(..)
       , TLSContext
       , explicitToImplicit
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

import Control.Concurrent.MVar
import Data.ByteString.Lazy(ByteString)
import qualified TLS.Context.Explicit as E
import TLS.CipherSuite.Encryptor
import TLS.CompressionMethod
import TLS.Context.Explicit(IOSystem(..))
import TLS.Handshake.Type

newtype TLSContext = Con { getMVar :: MVar E.TLSContext }

explicitToImplicit :: E.TLSContext -> IO TLSContext
explicitToImplicit c = Con `fmap` newMVar c

initialContext :: IOSystem -> IO TLSContext
initialContext iosys =
  do con   <- E.initialContext iosys
     conMV <- newMVar con
     return (Con conMV)

startRecording :: TLSContext -> IO ()
startRecording c = modifyMVar_ (getMVar c) (\ x -> return (E.startRecording x))

endRecording :: TLSContext -> IO ()
endRecording c = modifyMVar_ (getMVar c) (\ x -> return (E.startRecording x))

emitRecording :: TLSContext -> IO ByteString
emitRecording c = withMVar (getMVar c) (\ x -> return (E.emitRecording x))

setNextCipherSuite :: TLSContext -> Compressor -> Encryptor -> IO ()
setNextCipherSuite c comp enc =
  modifyMVar_ (getMVar c) (\ x -> return (E.setNextCipherSuite x comp enc))

nextHandshakeRecord :: IsHandshake a b =>
                       TLSContext -> b ->
                       IO a
nextHandshakeRecord c ctxt =
  modifyMVar (getMVar c) (flip E.nextHandshakeRecord ctxt)

maybeGetHandshake :: IsHandshake a b =>
                     TLSContext -> b ->
                     IO (Maybe a)
maybeGetHandshake c ctxt =
  modifyMVar (getMVar c) (flip E.maybeGetHandshake ctxt)

writeHandshake :: IsHandshake a b =>
                  TLSContext -> a ->
                  IO ()
writeHandshake c v = modifyMVar_ (getMVar c) (flip E.writeHandshake v)

sendChangeCipherSpec :: TLSContext -> IO ()
sendChangeCipherSpec c = modifyMVar_ (getMVar c) E.sendChangeCipherSpec

receiveChangeCipherSpec :: TLSContext -> IO ()
receiveChangeCipherSpec c = modifyMVar_ (getMVar c) E.receiveChangeCipherSpec

readTLS :: TLSContext -> IO ByteString
readTLS c = modifyMVar (getMVar c) E.readTLS

writeTLS :: TLSContext -> ByteString -> IO ()
writeTLS c bstr = modifyMVar_ (getMVar c) (flip E.writeTLS bstr)
 
