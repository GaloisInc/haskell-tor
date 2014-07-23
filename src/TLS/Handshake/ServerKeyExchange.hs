{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.Handshake.ServerKeyExchange(
         ServerKeyExchange(..)
       , putServerKeyExchange
       , getServerKeyExchange
       )
 where

import Control.Applicative
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import TLS.CipherSuite
import TLS.CipherSuite.KeyExchangeAlgorithm
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.SignatureAlgorithm
import TLS.DiffieHellman
import TLS.Handshake.Type

data ServerKeyExchange = ServerKeyExchangeAnon {
                           skeParams :: ServerDHParams
                         }
                       | ServerKeyExchangeSigned {
                           skeParams       :: ServerDHParams
                         , skeHashAlg      :: HashAlgorithm
                         , skeSignatureAlg :: SignatureAlgorithm
                         , skeSignature    :: ByteString
                         }
 deriving (Eq, Show)

instance IsHandshake ServerKeyExchange CipherSuite where
  handshakeType _ = TypeServerKeyExchange
  putHandshake    = putServerKeyExchange
  getHandshake    = getServerKeyExchange

putServerKeyExchange :: ServerKeyExchange -> Put
putServerKeyExchange (ServerKeyExchangeAnon x) =
  putServerDHParams x
putServerKeyExchange x@ServerKeyExchangeSigned{} =
  do putServerDHParams     (skeParams x)
     putHashAlgorithm      (skeHashAlg x)
     putSignatureAlgorithm (skeSignatureAlg x)
     let siglen = BS.length (skeSignature x)
     unless (siglen <= 65535) $
       fail "Signature length too long in ServerKeyExchange."
     putWord16be           (fromIntegral siglen)
     putLazyByteString     (skeSignature x)

getServerKeyExchange :: CipherSuite -> Get ServerKeyExchange
getServerKeyExchange cs =
  if | algo == ExchDH_anon ->
         ServerKeyExchangeAnon <$> getServerDHParams
     | (algo == ExchDHE_RSA) || (algo == ExchDHE_DSS) ->
         do params <- getServerDHParams
            hasha  <- getHashAlgorithm
            siga   <- getSignatureAlgorithm
            siglen <- getWord16be
            sig    <- getLazyByteString (fromIntegral siglen)
            return (ServerKeyExchangeSigned params hasha siga sig)
     | otherwise ->
         fail ("Should not be reading key exchange info with suite " ++ show cs)
 where algo = cipherKeyExchangeAlgorithm cs
