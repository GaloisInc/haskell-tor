import Control.Concurrent(forkIO,threadDelay)
import Control.Exception
import Control.Monad
import Crypto.Types.PubKey.RSA
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.ByteString.Base64.Lazy(decode)
import Data.ByteString.Lazy.Char8(pack)
import Data.List
import Data.Time
import Data.Word
import Network.Socket hiding (recv)
import System.IO
import System.Locale
import Tor.Circuit
import Tor.DataFormat.TorCell
import Tor.NetworkStack.System
import Tor.Options
import Tor.RouterDesc
import Tor.State

-- -----------------------------------------------------------------------------

getRouter' :: a -> b -> IO RouterDesc
getRouter' _ _ =
  do str <- readFile "/Users/awick/.tor/keys/secret_onion_key"
     let Right bstr = decode (pack (concat (init (tail (lines str)))))
     let Right asn1s = decodeASN1 DER bstr
     case fromASN1 asn1s of
       Left err -> fail ("ASN1 decode error: " ++ err)
       Right (x, _) ->
         return RouterDesc {
           routerNickname    = "localhost"
         , routerIPv4Address = "127.0.0.1"
         , routerORPort      = 9001
         , routerOnionKey    = private_pub x
         }

buildCircularCircuit :: TorState ls s -> IO ()
buildCircularCircuit torState = catch tryCircular notPublic
 where
  notPublic :: SomeException -> IO ()
  notPublic e =
    do logMsg torState ("Couldn't build route to myself: " ++ show e)
       logMsg torState "I hope this is an output-only, non-relay node."
  --
  tryCircular =
    do initRouter <- getRouter torState []
       circ       <- throwLeft =<< createCircuit torState initRouter
       myAddrs    <- getLocalAddresses torState
       logMsg torState ("My publicly-routable IP address(es): " ++
                        intercalate "," (map show myAddrs))
       midRouter  <- getRouter torState [NotRouter initRouter]
       putStrLn ("Extending router to " ++ routerIPv4Address midRouter)
       ()         <- throwLeft =<< extendCircuit torState circ midRouter
       myDesc     <- getRouter torState [NotRouter initRouter, NotRouter midRouter]
       putStrLn ("Extending router to " ++ routerIPv4Address myDesc)
       ()         <- throwLeft =<< extendCircuit torState circ myDesc
       logMsg torState ("Cycle circuit created. Yay! Closing it.")
       destroyCircuit circ NoReason


main :: IO ()
main = runDefaultMain $ \ flags ->
  do logger        <- generateLogger flags
     let onionPort =  getOnionPort flags
     torState      <- initializeTorState systemNetworkStack logger flags
     _             <- forkIO (torServerPort torState onionPort)
     buildCircularCircuit torState
     forever (threadDelay 100000000)

torServerPort :: TorState a b -> Word16 -> IO ()
torServerPort torState onionPort =
  do lsock <- socket AF_INET Stream defaultProtocol
     bind lsock (SockAddrInet (PortNum onionPort) iNADDR_ANY)
     listen lsock 3
     logMsg torState ("Waiting for Tor connections on port " ++ show onionPort)
     forever $ do (sock, addr) <- accept lsock
                  logMsg torState ("Accepted TCP connection from " ++ show addr)
                  forkIO (runServerConnection torState sock)

runServerConnection :: TorState a b -> Socket -> IO ()
runServerConnection torState sock =
  do undefined torState sock

-- -----------------------------------------------------------------------------

generateLogger :: [Flag] -> IO (String -> IO ())
generateLogger []                 = return (makeLogger stdout)
generateLogger ((OutputLog fp):_) = makeLogger `fmap` openFile fp AppendMode
generateLogger (_:rest)           = generateLogger rest

makeLogger :: Handle -> String -> IO ()
makeLogger h msg =
  do now <- getCurrentTime
     let tstr = formatTime defaultTimeLocale "[%d%b%Y %X] " now
     hPutStrLn h (tstr ++ msg)

throwLeft :: Either String b -> IO b
throwLeft (Left s)  = fail s
throwLeft (Right x) = return x
