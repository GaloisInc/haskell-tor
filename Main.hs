import Control.Concurrent
import Control.Monad
import Crypto.Random.DRBG
import Data.ByteString.Lazy(hGet, hPut)
import Data.ByteString.Lazy.Char8(pack)
import Data.List
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import System.IO(IOMode(ReadWriteMode), hFlush)
import TLS.Certificate
import TLS.Certificate.ClientCertificateType
import TLS.CipherSuite
import TLS.CipherSuite.HashAlgorithm
import TLS.CipherSuite.KeyExchangeAlgorithm
import TLS.CipherSuite.SignatureAlgorithm
import TLS.CompressionMethod
import TLS.Context.Explicit
import TLS.DiffieHellman
import TLS.Negotiation

main :: IO ()
main =
  do -- generate a fresh base certificate
     g <- newGenIO :: IO HashDRBG
     let (cert, privkey, _) = generateCertificate g
         serverOpts         = TLSServerOptions {
           acceptableCAs       = []
         , acceptableCertTypes = [TypeRSASign]
         , acceptableSigAlgs   = Just (map (\ x -> (SigRSA, x))
                                           [HashMD5, HashSHA1, HashSHA224,
                                            HashSHA256, HashSHA384, HashSHA512])
         , serverCertificates  = [cert]
         , serverChooseCipherSuite  = chooseCipher
         , serverChooseCompression  = chooseCompression
         , serverDiffieHellmanGroup = modp4096
         , serverPrivateKey         = privkey
         , shouldAskForClientCert   = True
         , validateClientCerts      = \ _ -> return True
         }
     lsock <- socket AF_INET Stream defaultProtocol
     bind lsock (SockAddrInet 7532 iNADDR_ANY)
     listen lsock 4
     forever $
       do (sock, _) <- accept lsock
          forkIO $ 
            do sockIO <- socketIO sock
               con <- serverNegotiate sockIO serverOpts
               putStrLn "Connected!"
               _ <- writeTLS con (pack "Hello, world!")
               putStrLn "Wrote message!"

--     -- connect to the server
--     sock <- socket AF_INET Stream defaultProtocol
--     addr <- inet_addr "127.0.0.1"
--     connect sock (SockAddrInet 7532 addr)
--     sockIO <- socketIO sock
--     con <- clientNegotiate sockIO defaultClientOptions{
--              clientCertificates = [cert]
--            , clientPrivateKey   = privkey
--            }
--     putStrLn "Connection succeeded!"
--     (_, bstr) <- readTLS con
--     putStrLn ("READ: " ++ show bstr)

socketIO :: Socket -> IO IOSystem
socketIO sock =
 do hndl <- socketToHandle sock ReadWriteMode
    return (IOSystem (hGet hndl) (hPut hndl) (hFlush hndl))

chooseCipher :: [CipherSuite] -> Maybe CipherSuite
chooseCipher [] = Nothing
chooseCipher (x:rest)
  | cipherKeyExchangeAlgorithm x /= ExchDHE_RSA = chooseCipher rest
  | not ("AES" `isInfixOf` cipherName x)        = chooseCipher rest
  | otherwise                                   = Just x

chooseCompression :: [CompressionMethod] -> Maybe CompressionMethod
chooseCompression [] = Nothing
chooseCompression (x:rest)
  | x == nullCompression = Just x
  | otherwise            = chooseCompression rest
