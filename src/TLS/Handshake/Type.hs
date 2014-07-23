{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |TLS 1.2 Handshake message types, along with a helpful class for Handshakes.
module TLS.Handshake.Type(
         HandshakeType(..)
       , IsHandshake(..)
       , putHandshakeType
       , getHandshakeType
       )
 where

import Data.Binary.Get
import Data.Binary.Put

-- |A handy class for declaring TLS 1.2 handshake message kinds.
class (Eq a, Show a, Show b) => IsHandshake a b | a -> b where
  -- |The type of handshake this is. Should not evaluate its argument.
  handshakeType :: a -> HandshakeType
  -- |Serialize the given handshake submessage.
  putHandshake  :: a -> Put
  -- |Deserialize the given handshake from a ByteString.
  getHandshake  :: b -> Get a

-- |The kinds of Handshakes TLS 1.2 defines.
data HandshakeType = TypeHelloRequest
                   | TypeClientHello
                   | TypeServerHello
                   | TypeCertificate
                   | TypeServerKeyExchange
                   | TypeCertificateRequest
                   | TypeServerHelloDone
                   | TypeCertificateVerify
                   | TypeClientKeyExchange
                   | TypeFinished
 deriving (Eq, Show)

-- |Put a handshake type.
putHandshakeType :: HandshakeType -> Put
putHandshakeType TypeHelloRequest       = putWord8 0
putHandshakeType TypeClientHello        = putWord8 1
putHandshakeType TypeServerHello        = putWord8 2
putHandshakeType TypeCertificate        = putWord8 11
putHandshakeType TypeServerKeyExchange  = putWord8 12
putHandshakeType TypeCertificateRequest = putWord8 13
putHandshakeType TypeServerHelloDone    = putWord8 14
putHandshakeType TypeCertificateVerify  = putWord8 15
putHandshakeType TypeClientKeyExchange  = putWord8 16
putHandshakeType TypeFinished           = putWord8 20

-- |Get a handshake type. Will 'fail' if the value in the ByteString does
-- not match a known, RFC 5246 handshake message type.
getHandshakeType :: Get HandshakeType
getHandshakeType =
  do b <- getWord8
     case b of
       0  -> return TypeHelloRequest
       1  -> return TypeClientHello
       2  -> return TypeServerHello
       11 -> return TypeCertificate
       12 -> return TypeServerKeyExchange
       13 -> return TypeCertificateRequest
       14 -> return TypeServerHelloDone
       15 -> return TypeCertificateVerify
       16 -> return TypeClientKeyExchange
       20 -> return TypeFinished
       _  -> fail "Invalid value for HandshakeType"
