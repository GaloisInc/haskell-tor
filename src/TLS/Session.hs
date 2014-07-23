{-# LANGUAGE MultiWayIf #-}
module TLS.Session(
         Session(..)
       , getSession
       , putSession
       , generateSession
       )
 where

import Control.Applicative
import Crypto.Random
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString as BSS
import qualified Data.ByteString.Lazy as BS

data Session = EmptySession | Session ByteString
 deriving (Eq, Show)

putSession :: Session -> Put
putSession EmptySession = putWord8 0
putSession (Session bstr)
  | BS.length bstr > 32 = fail "putSession: Session too large."
  | otherwise           =
     do putWord8 (fromIntegral (BS.length bstr))
        putLazyByteString bstr

getSession :: Get Session
getSession =
  do l <- fromIntegral <$> getWord8
     if | l == 0  -> return EmptySession
        | l <= 32 -> Session <$> getLazyByteString l
        | l > 32  -> fail "Session length too long!"

-- ----------------------------------------------------------------------------

generateSession :: CryptoRandomGen g => g -> Either GenError (Session, g)
generateSession g =
  case genBytes 1 g of
    Left err -> Left err
    Right (lenbstr, g') ->
      let [len8] = BSS.unpack lenbstr
          len     = fromIntegral (len8 `mod` 32) + 1
      in case genBytes len g' of
           Left err -> Left err
           Right (bstr, g'') ->
             Right (Session (BS.fromChunks [bstr]), g'')
