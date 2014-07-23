module TLS.Handshake.Extension(
         Extension(..)
       , putExtension
       , getExtension
       , legalServerExtensions
       , extensionsAllow
       )
 where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Word
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.SignatureAlgorithm

data Extension = ExtSignatureAlgorithm [(HashAlgorithm, SignatureAlgorithm)]
               | ExtUnknown            Word16 ByteString
 deriving (Eq, Show)

putExtension :: Extension -> Put
putExtension (ExtSignatureAlgorithm hsigs) =
  do putWord16be 13
     let bstr = runPut (putHashSigs hsigs)
     putWord16be (fromIntegral (BS.length bstr))
     putLazyByteString bstr
putExtension (ExtUnknown t bstr) =
  do putWord16be t
     putWord16be (fromIntegral (BS.length bstr))
     putLazyByteString bstr

getExtension :: Get Extension
getExtension =
  do t <- getWord16be
     l <- getWord16be
     b <- getLazyByteString (fromIntegral l)
     case t of
       13 -> return (ExtSignatureAlgorithm (runGet getHashSigs b))
       _  -> return (ExtUnknown t b)

-- ----------------------------------------------------------------------------

putHashSigs :: [(HashAlgorithm, SignatureAlgorithm)] -> Put
putHashSigs hsigs =
  forM_ hsigs $ \ (hash, sig) ->
    do putHashAlgorithm hash
       putSignatureAlgorithm sig

getHashSigs :: Get [(HashAlgorithm, SignatureAlgorithm)]
getHashSigs =
  do done <- isEmpty
     if done
        then return []
        else do hash <- getHashAlgorithm
                sig  <- getSignatureAlgorithm
                ((hash, sig) :) `fmap` getHashSigs

-- ----------------------------------------------------------------------------

legalServerExtensions :: [Extension] -> [Extension] -> Bool
legalServerExtensions []       _     = True
legalServerExtensions (f:rest) cexts
  | f `elem` cexts = legalServerExtensions rest cexts
  | otherwise      = False

extensionsAllow :: SignatureAlgorithm -> HashAlgorithm -> [Extension] -> Bool
extensionsAllow _     _    []         = True
extensionsAllow hasha siga extensions = any allowed extensions
 where
  allowed (ExtUnknown _ _) = False
  allowed (ExtSignatureAlgorithm algs) = any (== (siga, hasha)) algs

