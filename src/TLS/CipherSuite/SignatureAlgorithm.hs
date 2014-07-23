module TLS.CipherSuite.SignatureAlgorithm(
         SignatureAlgorithm(..)
       , putSignatureAlgorithm
       , getSignatureAlgorithm
       )
 where

import Data.Binary.Get
import Data.Binary.Put

data SignatureAlgorithm = SigAnonymous | SigRSA | SigDSA | SigECDSA
 deriving (Eq, Show)

putSignatureAlgorithm :: SignatureAlgorithm -> Put
putSignatureAlgorithm SigAnonymous = putWord8 0
putSignatureAlgorithm SigRSA       = putWord8 1
putSignatureAlgorithm SigDSA       = putWord8 2
putSignatureAlgorithm SigECDSA     = putWord8 3

getSignatureAlgorithm :: Get SignatureAlgorithm
getSignatureAlgorithm =
  do b <- getWord8
     case b of
       0 -> return SigAnonymous
       1 -> return SigRSA
       2 -> return SigDSA
       3 -> return SigECDSA
       _ -> fail ("Invalid code for SignatureAlgorithm: " ++ show b)

