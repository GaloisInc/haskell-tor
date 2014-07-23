module TLS.CipherSuite.KeyExchangeAlgorithm(
         KeyExchangeAlgorithm(..)
       )
 where

data KeyExchangeAlgorithm = ExchDHE_DSS
                          | ExchDHE_RSA
                          | ExchDH_anon
                          | ExchDH_DSS
                          | ExchDH_RSA
                          | ExchRSA
                          | ExchNull
 deriving (Eq, Show)
