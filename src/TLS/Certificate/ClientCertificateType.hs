module TLS.Certificate.ClientCertificateType(
         ClientCertificateType(..)
       , putClientCertificateType
       , getClientCertificateType
       )
 where

import Data.Binary.Get
import Data.Binary.Put

data ClientCertificateType = TypeRSASign        | TypeDSSSign
                           | TypeRSAFixedDH     | TypeDSSFixedDH
                           | TypeRSAEphemeralDH | TypeDSSEphemeralDH
                           | TypeFortezzaDMS
 deriving (Show, Eq)

putClientCertificateType :: ClientCertificateType -> Put
putClientCertificateType TypeRSASign        = putWord8 1
putClientCertificateType TypeDSSSign        = putWord8 2
putClientCertificateType TypeRSAFixedDH     = putWord8 3
putClientCertificateType TypeDSSFixedDH     = putWord8 4
putClientCertificateType TypeRSAEphemeralDH = putWord8 5
putClientCertificateType TypeDSSEphemeralDH = putWord8 6
putClientCertificateType TypeFortezzaDMS    = putWord8 20

getClientCertificateType :: Get ClientCertificateType
getClientCertificateType =
  do x <- getWord8
     case x of
       1  -> return TypeRSASign
       2  -> return TypeDSSSign
       3  -> return TypeRSAFixedDH
       4  -> return TypeDSSFixedDH
       5  -> return TypeRSAEphemeralDH
       6  -> return TypeDSSEphemeralDH
       20 -> return TypeFortezzaDMS
       _  -> fail "Illegal value for ClientCertificateType"
