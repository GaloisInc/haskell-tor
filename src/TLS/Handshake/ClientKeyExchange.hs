{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.Handshake.ClientKeyExchange(
         ClientKeyExchange(..)
       , putClientKeyExchange
       , getClientKeyExchange
       )
 where

import Control.Applicative
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import TLS.CipherSuite.KeyExchangeAlgorithm
import TLS.Handshake.Type

data ClientKeyExchange = ClientKeyExchangeEncrypt ByteString
                       | ClientKeyExchangeDHImplicit
                       | ClientKeyExchangeDHExplicit ByteString
 deriving (Eq, Show)

instance IsHandshake ClientKeyExchange KeyExchangeAlgorithm where
  handshakeType _ = TypeClientKeyExchange
  putHandshake    = putClientKeyExchange
  getHandshake    = getClientKeyExchange

putClientKeyExchange :: ClientKeyExchange -> Put
putClientKeyExchange (ClientKeyExchangeEncrypt x) =
  do unless (BS.length x <= 65535) $ fail "EncryptedPreMasterSecret too large!"
     putWord16be (fromIntegral (BS.length x))
     putLazyByteString x
putClientKeyExchange (ClientKeyExchangeDHImplicit) =
  return ()
putClientKeyExchange (ClientKeyExchangeDHExplicit x) =
  do unless (BS.length x <= 65535) $ fail "Explicit PublicValueEnc too large!"
     unless (BS.length x >= 1) $ fail "Explicit PublicValueEnc too small!"
     putWord16be (fromIntegral (BS.length x))
     putLazyByteString x

getClientKeyExchange :: KeyExchangeAlgorithm -> Get ClientKeyExchange
getClientKeyExchange ExchRSA =
  do len <- getWord16be
     ClientKeyExchangeEncrypt <$> getLazyByteString (fromIntegral len)
getClientKeyExchange _ =
  do done <- isEmpty
     if done
       then return ClientKeyExchangeDHImplicit
       else do l' <- fromIntegral <$> getWord16be
               unless (l' > 0) $ fail "Public DH value too small"
               ClientKeyExchangeDHExplicit <$> getLazyByteString l'
