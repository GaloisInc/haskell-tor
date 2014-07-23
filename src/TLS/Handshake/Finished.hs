{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.Handshake.Finished(
         Finished(..)
       , getFinished
       , putFinished
       )
 where

import Control.Applicative
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import TLS.Handshake.Type

data Finished = Finished ByteString
 deriving (Eq, Show)

instance IsHandshake Finished () where
  handshakeType _ = TypeFinished
  putHandshake    = putFinished
  getHandshake _  = getFinished

putFinished :: Finished -> Put
putFinished (Finished x) = putLazyByteString x

getFinished :: Get Finished
getFinished = Finished <$> getRemainingLazyByteString
