{-# LANGUAGE RecordWildCards #-}
import Control.Concurrent(forkIO,threadDelay)
import Control.Exception
import Control.Monad
import qualified Data.ByteString.Char8 as BSC
import Data.Hourglass
import Data.Hourglass.Now
import Data.List
import Data.Word
import Network.TLS
import System.IO
import Tor.DataFormat.TorAddress
import Tor.Circuit
import Tor.DataFormat.TorCell
import Tor.Link
import Tor.NetworkStack
import Tor.NetworkStack.System
import Tor.Options
import Tor.RouterDesc
import Tor.State


main :: IO ()
main = runDefaultMain $ \ flags ->
  do logger        <- generateLogger flags
     let onionPort =  getOnionPort flags
     torState      <- initializeTorState systemNetworkStack logger flags
     startTorServerPort torState onionPort
     buildCircularCircuit torState
     forever (threadDelay 100000000)

buildCircularCircuit :: HasBackend s => TorState ls s -> IO ()
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
       lastRouter <- getRouter torState [NotRouter initRouter,
                                         NotRouter midRouter,
                                         NotTorAddr (IP4 "37.49.35.221"),
                                         NotTorAddr (IP4 "62.210.74.143"),
                                         NotTorAddr (IP4 "162.248.160.151"),
                                         NotTorAddr (IP4 "109.235.50.163"),
                                         ExitNodeAllowing (IP4 "66.193.37.213") 80]
       putStrLn ("Extending router to " ++ routerIPv4Address lastRouter)
       ()         <- throwLeft =<< extendCircuit torState circ lastRouter
       nms        <- resolveName circ "galois.com"
       putStrLn ("Resolved galois.com to " ++ show nms)
       putStrLn ("Exit rules: " ++ show (routerExitRules lastRouter))
       con        <- connectToHost circ (Hostname "uhsure.com") 80
       putStrLn ("Built connection!")
       torWrite con (buildGet "http://uhsure.com/")
       putStrLn ("Wrote GET")
       resp <- torRead con 300
       putStrLn ("Got response: " ++ show resp)
       destroyCircuit circ NoReason
  --
  buildGet str = result
   where
    result      = BSC.pack (requestLine ++ userAgent ++ crlf)
    requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
    userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
    crlf        = "\r\n"


startTorServerPort :: HasBackend sock => TorState lsock sock -> Word16 -> IO ()
startTorServerPort torState onionPort =
  do let ns = getNetworkStack torState
     lsock <- listen ns onionPort
     logMsg torState ("Waiting for Tor connections on port " ++ show onionPort)
     _ <- forkIO $ forever $
       do (sock, addr) <- accept ns lsock
          forkIO (acceptIncomingLink torState sock addr)
     return ()

-- -----------------------------------------------------------------------------

generateLogger :: [Flag] -> IO (String -> IO ())
generateLogger []                 = return (makeLogger stdout)
generateLogger ((OutputLog fp):_) = makeLogger `fmap` openFile fp AppendMode
generateLogger (_:rest)           = generateLogger rest

makeLogger :: Handle -> String -> IO ()
makeLogger h msg =
  do now <- getCurrentTime
     hPutStrLn h (timePrint timeFormat now ++ msg)
 where
  timeFormat = [Format_Text '[', Format_Year4, Format_Text '-', Format_Month2,
                Format_Text '-', Format_Day2, Format_Text ' ', Format_Hour,
                Format_Text ':', Format_Minute, Format_Text ']',
                Format_Text ' ']

throwLeft :: Either String b -> IO b
throwLeft (Left s)  = fail s
throwLeft (Right x) = return x
