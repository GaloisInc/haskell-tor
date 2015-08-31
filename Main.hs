{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP #-}
import Control.Concurrent(forkIO,threadDelay)
import Control.Exception
import Control.Monad
import Data.ByteString.Char8(pack)
import Data.Hourglass
import Data.Hourglass.Now
import Data.List
import Data.Word
import Network.TLS
import Tor.DataFormat.TorAddress
import Tor.Circuit
import Tor.DataFormat.TorCell
import Tor.Link
import Tor.NetworkStack
import Tor.Options
import Tor.RouterDesc
import Tor.State

#ifdef HaLVM_HOST_OS
import Hans.Device.Xen
import Hans.DhcpClient
import Hans.NetworkStack hiding (listen, accept)
import Hypervisor.Console
import Hypervisor.XenStore
import Tor.NetworkStack.Hans
import XenDevice.NIC
#else
import Tor.NetworkStack.System
#endif

main :: IO ()
main = runDefaultMain $ \ flags ->
  do (ns, logger)  <- initializeSystem flags
     let onionPort =  getOnionPort flags
     torState      <- initializeTorState ns logger flags
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
    do logMsg torState "Getting initial router.\n"
       initRouter <- getRouter torState []
       logMsg torState "Creating circuit.\n"
       circ       <- throwLeft =<< createCircuit torState initRouter
       logMsg torState "Getting local address.\n"
       myAddrs    <- getLocalAddresses torState
       logMsg torState ("My publicly-routable IP address(es): " ++
                        intercalate "," (map show myAddrs))
       logMsg torState "Getting intermediate router.\n"
       midRouter  <- getRouter torState [NotRouter initRouter]
       logMsg torState ("Extending router to " ++ routerIPv4Address midRouter)
       ()         <- throwLeft =<< extendCircuit torState circ midRouter
       lastRouter <- getRouter torState [NotRouter initRouter,
                                         NotRouter midRouter,
                                         NotTorAddr (IP4 "37.49.35.221"),
                                         NotTorAddr (IP4 "62.210.74.143"),
                                         NotTorAddr (IP4 "162.248.160.151"),
                                         NotTorAddr (IP4 "109.235.50.163"),
                                         ExitNodeAllowing (IP4 "66.193.37.213") 80]
       logMsg torState ("Extending router to " ++ routerIPv4Address lastRouter)
       ()         <- throwLeft =<< extendCircuit torState circ lastRouter
       nms        <- resolveName circ "galois.com"
       logMsg torState ("Resolved galois.com to " ++ show nms)
       logMsg torState ("Exit rules: " ++ show (routerExitRules lastRouter))
       con        <- connectToHost circ (Hostname "uhsure.com") 80
       logMsg torState ("Built connection!")
       torWrite con (buildGet "http://uhsure.com/")
       logMsg torState ("Wrote GET")
       resp <- torRead con 300
       logMsg torState ("Got response: " ++ show resp)
       destroyCircuit circ NoReason
  --
  buildGet str = result
   where
    result      = pack (requestLine ++ userAgent ++ crlf)
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

initializeSystem :: [Flag] ->
                    IO (TorNetworkStack Socket Socket, String -> IO ())
#ifdef HaLVM_HOST_OS
initializeSystem _ =
  do con    <- initXenConsole
     xs     <- initXenStore
     ns     <- newNetworkStack
     macstr <- findNIC xs
     putStrLn ("Using NIC with MAC address " ++ macstr)
     nic    <- openNIC xs macstr
     putStrLn ("Started the NIC.")
     let mac = read macstr
     addDevice ns mac (xenSend nic) (xenReceiveLoop nic)
     putStrLn ("Added the device.")
     deviceUp ns mac
     putStrLn ("Started the device.")
     ipaddr <- dhcpDiscover ns mac
     putStrLn ("Node has IP address " ++ show ipaddr)
     return (hansNetworkStack ns, makeLogger (\ x -> writeConsole con (x ++ "\n")))
 where
  findNIC xs =
    do nics <- listNICs xs
       case nics of
         []    -> threadDelay 1000000 >> findNIC xs
         (x:_) -> return x
#else
initializeSystem flags =
  do logger <- generateLogger flags
     return (systemNetworkStack, logger)

generateLogger :: [Flag] -> IO (String -> IO ())
generateLogger []                 = return (makeLogger (hPutStrLn stdout))
generateLogger ((OutputLog fp):_) = do h <- openFile fp AppendMode
                                       return (makeLogger (hPutStrLn h))
generateLogger (_:rest)           = generateLogger rest
#endif

-- -----------------------------------------------------------------------------

makeLogger :: (String -> IO ()) -> String -> IO ()
makeLogger out msg =
  do now <- getCurrentTime
     out (timePrint timeFormat now ++ msg)
 where
  timeFormat = [Format_Text '[', Format_Year4, Format_Text '-', Format_Month2,
                Format_Text '-', Format_Day2, Format_Text ' ', Format_Hour,
                Format_Text ':', Format_Minute, Format_Text ']',
                Format_Text ' ']

throwLeft :: Either String b -> IO b
throwLeft (Left s)  = fail s
throwLeft (Right x) = return x
