module Test.KeyExchangeAlgorithm where

import Test.QuickCheck
import TLS.CipherSuite.KeyExchangeAlgorithm

instance Arbitrary KeyExchangeAlgorithm where
  arbitrary = elements [ ExchDHE_DSS, ExchDHE_RSA, ExchDH_anon, ExchDH_DSS,
                         ExchDH_RSA, ExchRSA, ExchNull ]
