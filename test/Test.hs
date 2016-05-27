import Test.Crypto(testCrypto)
import Test.Framework.Runners.Console(defaultMain)
-- import Test.Handshakes
-- import Test.HybridEncrypt
-- import Test.Link
import Test.Network(testTestInternet)
-- import Test.TorCell

main :: IO ()
main =
  defaultMain [
    testCrypto
--  , torCellTests
--  , hybridEncryptionTest
--  , handshakeTests
  , testTestInternet
--  , linkTests
  ]
