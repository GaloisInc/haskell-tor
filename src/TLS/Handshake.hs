{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}
module TLS.Handshake(
         RawHandshake(..)
       , getRawHandshake
       , putRawHandshake
       , encodeHandshake
       , decodeHandshake
       )
 where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Word24
import TLS.Handshake.Type

data RawHandshake = RawHandshake {
    hsType    :: HandshakeType
  , hsPayload :: ByteString
  }
 deriving (Eq, Show)

putRawHandshake :: RawHandshake -> Put
putRawHandshake hs =
  do putHandshakeType (hsType hs)
     let payload = hsPayload hs
     unless (BS.length payload < 16777216) $
       fail "Handshake payload too large!"
     putWord24 (fromIntegral (BS.length payload))
     putLazyByteString payload

getRawHandshake :: Get RawHandshake
getRawHandshake =
  do hsType    <- getHandshakeType
     len       <- getWord24
     hsPayload <- getLazyByteString (fromIntegral len)
     return RawHandshake{..}

-- ----------------------------------------------------------------------------

encodeHandshake :: IsHandshake a b => a -> RawHandshake
encodeHandshake x = RawHandshake (handshakeType x) (runPut (putHandshake x))

decodeHandshake :: IsHandshake a b => b -> RawHandshake -> Either String a
decodeHandshake ctxt raw =
  case runGetOrFail (typeTieDecode undefined ctxt) (hsPayload raw) of
    Left  (_, _, err) -> Left ("Handshake decode error: " ++ show err)
    Right (_, _, res)
      | handshakeType res /= hsType raw -> Left "Handshake type match failure."
      | otherwise                       -> Right res
 where
  typeTieDecode :: IsHandshake a b => a -> b -> Get a
  typeTieDecode _ ctxt' = getHandshake ctxt'
