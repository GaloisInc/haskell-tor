{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module TLS.Handshake.ServerHello(
         ServerHello(..)
       , putServerHello
       , getServerHello
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

data ServerHello = ServerHello {
       shServerVersion      :: ProtocolVersion
     , shRandom             :: Random
     , shSessionID          :: Session
     , shCipherSuite        :: CipherSuite
     , shCompressionMethod  :: CompressionMethod
     , shExtensions         :: [Extension]
     }
 deriving (Eq, Show)

instance IsHandshake ServerHello () where
  handshakeType _ = TypeServerHello
  putHandshake    = putServerHello
  getHandshake _  = getServerHello rfc5246CipherSuites rfc5246CompressionMethods

putServerHello :: ServerHello -> Put
putServerHello sh =
  do putProtocolVersion   (shServerVersion sh)
     putRandom            (shRandom sh)
     putSession           (shSessionID sh)
     putCipherSuite       (shCipherSuite sh)
     putCompressionMethod (shCompressionMethod sh)
     when (length (shExtensions sh) > 0) $
       putVector 0 65535 putWord16be putExtension (shExtensions sh)

getServerHello :: [CipherSuite] -> [CompressionMethod] -> Get ServerHello
getServerHello cipherSuites compMethods =
  do shServerVersion     <- getProtocolVersion
     shRandom            <- getRandom
     shSessionID         <- getSession
     shCipherSuite       <- getCipherSuite cipherSuites
     shCompressionMethod <- getCompressionMethod compMethods
     hasExtensions       <- not <$> isEmpty
     if hasExtensions
        then do shExtensions <- getVector 0 65536 getWord16be getExtension
                return ServerHello{..}
        else do let shExtensions = []
                return ServerHello{..}
