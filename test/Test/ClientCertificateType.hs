module Test.ClientCertificateType(clientCertificateTypeTests) where

import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Certificate.ClientCertificateType

instance Arbitrary ClientCertificateType where
  arbitrary = elements [TypeRSASign, TypeDSSSign, TypeRSAFixedDH,
                        TypeDSSFixedDH, TypeRSAEphemeralDH, TypeDSSEphemeralDH,
                        TypeFortezzaDMS ]

-- ----------------------------------------------------------------------------

prop_ClientCertTypeSerial :: ClientCertificateType -> Bool
prop_ClientCertTypeSerial =
  serialProp getClientCertificateType putClientCertificateType

clientCertificateTypeTests :: Test
clientCertificateTypeTests = testProperty "ClientCertificateType serializes"
                                          prop_ClientCertTypeSerial

