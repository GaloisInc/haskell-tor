{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.Handshake.HelloRequest(
         HelloRequest(..)
       , putHelloRequest
       , getHelloRequest
       )
 where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.Word24
import TLS.Handshake.Type

data HelloRequest = HelloRequest
 deriving (Eq, Show)

instance IsHandshake HelloRequest () where
  handshakeType _ = TypeHelloRequest
  putHandshake    = putHelloRequest
  getHandshake _  = getHelloRequest

putHelloRequest :: HelloRequest -> Put
putHelloRequest _ =
  do putHandshakeType TypeHelloRequest
     putWord24 0

getHelloRequest :: Get HelloRequest
getHelloRequest =
  do t <- getHandshakeType
     unless (t == TypeHelloRequest) $
       fail "Wrong type for HelloRequest."
     l <- getWord24
     unless (l == 0) $
       fail "Wrong length for HelloRequest."
     return HelloRequest

