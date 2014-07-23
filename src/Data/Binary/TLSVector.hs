{-# LANGUAGE MultiWayIf #-}
-- |Standard combinators for serializing and deserializing vectors according
-- to the TLS 1.2 standard.
module Data.Binary.TLSVector(
         putVector
       , getVector
       )
 where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString.Lazy as BS
import Data.Int

putVector :: Integral a =>
             Int64 -> Int64 ->
             (a -> Put) -> (b -> Put) -> [b] ->
             Put
putVector minb maxb putSize putElement elems =
  do let elemsBS = runPut (mapM_ putElement elems)
         len     = BS.length elemsBS
     unless (len >= minb) $ fail "Too few elements in vector."
     unless (len <= maxb) $ fail "Too many elements in vector."
     putSize (fromIntegral len)
     putLazyByteString elemsBS

getVector :: Integral a =>
             Int64 -> Int64 ->
             Get a -> Get b ->
             Get [b]
getVector minb maxb getSize getElement =
  do len_in <- getSize
     let len = fromIntegral len_in
     unless (len >= minb) $ fail "Too few elements in input vector."
     unless (len <= maxb) $ fail "Too many elements in input vector."
     now <- bytesRead
     pullElements (now + len)
 where
  pullElements target =
    do now <- bytesRead
       if | now == target -> return []
          | now >  target -> fail "Misaligned elements in vector read."
          | otherwise     ->
              return (:) `ap` getElement `ap` pullElements target


