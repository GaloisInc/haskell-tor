{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module TLS.Handshake.ClientHello(
         ClientHello(..)
       , getClientHello
       , putClientHello
       )
 where

import Control.Applicative
import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.Binary.TLSVector
import TLS.CipherSuite
import TLS.CompressionMethod
import TLS.Handshake.Extension
import TLS.Handshake.Type
import TLS.Random
import TLS.ProtocolVersion
import TLS.Session

data ClientHello = ClientHello {
       chClientVersion      :: ProtocolVersion
     , chRandom             :: Random
     , chSessionID          :: Session
     , chCipherSuites       :: [CipherSuite]
     , chCompressionMethods :: [CompressionMethod]
     , chExtensions         :: [Extension]
     }
 deriving (Eq, Show)

instance IsHandshake ClientHello () where
  handshakeType _ = TypeClientHello
  putHandshake    = putClientHello
  getHandshake _  = getClientHello rfc5246CipherSuites rfc5246CompressionMethods

putClientHello :: ClientHello -> Put
putClientHello ch =
  do putProtocolVersion (chClientVersion ch)
     putRandom          (chRandom ch)
     putSession         (chSessionID ch)
     putVector 2 65536 putWord16be putCipherSuite       (chCipherSuites ch)
     putVector 1 255   putWord8    putCompressionMethod (chCompressionMethods ch)
     when (length (chExtensions ch) > 0) $
       putVector 0 65535 putWord16be putExtension (chExtensions ch)

getClientHello :: [CipherSuite] -> [CompressionMethod] -> Get ClientHello
getClientHello cipherSuites compMethods =
  do chClientVersion      <- getProtocolVersion
     chRandom             <- getRandom
     chSessionID          <- getSession
     chCipherSuites       <- getVector 2 65536 getWord16be
                                       (getCipherSuite cipherSuites)
     chCompressionMethods <- getVector 1 255 getWord8
                                       (getCompressionMethod compMethods)
     hasExtensions        <- not <$> isEmpty
     if hasExtensions
        then do chExtensions <- getVector 0 65535 getWord16be getExtension
                return ClientHello{..}
        else do let chExtensions = []
                return ClientHello{..}
