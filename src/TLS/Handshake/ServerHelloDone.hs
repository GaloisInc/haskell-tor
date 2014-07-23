{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.Handshake.ServerHelloDone(
         ServerHelloDone(..)
       , getServerHelloDone
       , putServerHelloDone
       )
 where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString.Lazy as BS
import TLS.Handshake.Type

data ServerHelloDone = ServerHelloDone
 deriving (Eq, Show)

instance IsHandshake ServerHelloDone () where
  handshakeType _ = TypeServerHelloDone
  putHandshake    = putServerHelloDone
  getHandshake _  = getServerHelloDone

putServerHelloDone :: ServerHelloDone -> Put
putServerHelloDone _ = return ()

getServerHelloDone :: Get ServerHelloDone
getServerHelloDone =
  do done <- isEmpty
     unless done $
       do bstr <- getRemainingLazyByteString
          fail ("Too much data in ServerHelloDone: " ++ show (BS.head bstr))
     return ServerHelloDone
