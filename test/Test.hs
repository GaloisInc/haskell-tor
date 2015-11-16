import Test.Framework.Runners.Console
import Test.Handshakes
import Test.HybridEncrypt
import Test.TorCell

main :: IO ()
main =
  defaultMain [
    torCellTests
  , hybridEncryptionTest
  , handshakeTests
  ]
