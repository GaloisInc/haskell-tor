{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.CipherSuite.Encryptor(
         TLSEncryption(..)
       , TLSEncryptionError(..)
       , Encryptor(..)
       , runEncrypt
       , runDecrypt
       )
 where

import Crypto.Random
import Data.ByteString.Lazy(ByteString)
import Data.Word
import TLS.ProtocolVersion
import TLS.Records.ContentType

data TLSEncryptionError = PaddingError
                        | MACCodingError
                        | RandomGenError GenError
                        | KeyLoadingError
 deriving (Eq, Show)

class TLSEncryption a where
  encrypt :: CryptoRandomGen g =>
             a -> g ->
             Word64 -> ContentType -> ProtocolVersion -> ByteString ->
             Either TLSEncryptionError (ByteString, a, g)
  decrypt :: a -> 
             Word64 -> ContentType -> ProtocolVersion -> ByteString ->
             Either TLSEncryptionError (ByteString, a)

data Encryptor = forall e. TLSEncryption e => Encryptor e

runEncrypt :: CryptoRandomGen g =>
              Encryptor -> g ->
              Word64 -> ContentType -> ProtocolVersion -> ByteString ->
              Either TLSEncryptionError (ByteString, Encryptor, g)
runEncrypt (Encryptor e) g s ct pv bstr =
  case encrypt e g s ct pv bstr of
    Left err              -> Left err
    Right (bstr', e', g') -> Right (bstr', Encryptor e', g') 

runDecrypt :: Encryptor ->
              Word64 -> ContentType -> ProtocolVersion -> ByteString ->
              Either TLSEncryptionError (ByteString, Encryptor)
runDecrypt (Encryptor e) seqnum ct pv bstr =
  case decrypt e seqnum ct pv bstr of
    Left err          -> Left err
    Right (bstr', e') -> Right (bstr', Encryptor e')

