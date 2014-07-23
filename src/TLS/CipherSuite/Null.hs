{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.CipherSuite.Null(
         NullKey(..)
       , nullHash
       )
 where

import Data.ByteString.Lazy(ByteString, empty)
import TLS.CipherSuite.Stream

data NullKey = NullKey

instance TLSStreamCipher NullKey where
  buildStreamKey  _      = NullKey
  encryptStream   _ bstr = bstr
  decryptStream   _ bstr = bstr

nullHash :: ByteString -> ByteString
nullHash _ = empty
