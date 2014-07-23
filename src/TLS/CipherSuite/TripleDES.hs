{-# LANGUAGE MultiParamTypeClasses #-}
module TLS.CipherSuite.TripleDES(TDESKey) where

import Crypto.Classes
import Data.Serialize
import Data.Tagged

data TDESKey = TDESKey

instance Serialize TDESKey where
  put _ = return ()
  get   = return TDESKey

instance BlockCipher TDESKey where
  blockSize        = Tagged 0
  encryptBlock _ _ = undefined
  decryptBlock _ _ = undefined
  buildKey       _ = undefined
  keyLength        = Tagged 0
