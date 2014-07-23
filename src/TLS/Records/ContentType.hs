module TLS.Records.ContentType(
         ContentType(..)
       , putContentType
       , getContentType
       )
 where

import Data.Binary.Get
import Data.Binary.Put

data ContentType = TypeChangeCipherSpec
                 | TypeAlert
                 | TypeHandshake
                 | TypeApplicationData
 deriving (Eq, Show)

putContentType :: ContentType -> Put
putContentType TypeChangeCipherSpec = putWord8 20
putContentType TypeAlert            = putWord8 21
putContentType TypeHandshake        = putWord8 22
putContentType TypeApplicationData  = putWord8 23

getContentType :: Get ContentType
getContentType =
  do x <- getWord8
     case x of
       20 -> return TypeChangeCipherSpec
       21 -> return TypeAlert
       22 -> return TypeHandshake
       23 -> return TypeApplicationData
       _  -> fail ("Illegal value for ContentType: " ++ show x)
