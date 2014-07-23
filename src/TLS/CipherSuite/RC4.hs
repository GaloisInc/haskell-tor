{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.CipherSuite.RC4(RC4Key) where

import TLS.CipherSuite.Stream

data RC4Key = RC4Key

instance TLSStreamCipher RC4Key where
  buildStreamKey  _   = undefined RC4Key
  encryptStream   _ _ = undefined
  decryptStream   _ _ = undefined

