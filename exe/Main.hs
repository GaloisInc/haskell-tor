{-# LANGUAGE CPP              #-}
{-# LANGUAGE RecordWildCards  #-}
import Control.Concurrent(forkIO)
import Tor
import Tor.Flags
import Tor.NetworkStack

#ifdef HaLVM_HOST_OS
import Hans.Device.Xen
import Hans.DhcpClient
import Hans.NetworkStack hiding (listen, accept)
import Hypervisor.Console
import Hypervisor.XenStore
import Tor.NetworkStack.Hans
import XenDevice.NIC
#else
import Hans.Device.Tap
import Hans.DhcpClient
import Hans.NetworkStack hiding (listen, accept)
import System.IO
import Tor.NetworkStack.Hans
import Tor.NetworkStack.System
#endif

main :: IO ()
main = runDefaultMain $ \ flags ->
  do (MkNS ns, logger)  <- initializeSystem flags
     let options   = defaultTorOptions{
                       torLog = logger
                     , torRelayOptions = Just defaultTorRelayOptions {
                            torOnionPort = getOnionPort flags
                          , torNickname  = getNickname flags
                          , torContact   = getContactInfo flags
                          }
                     }
     tor <- startTor ns options
     return ()
--
--     buildCircularCircuit torState
--
--buildCircularCircuit :: HasBackend s => TorState ls s -> IO ()
--buildCircularCircuit torState = catch tryCircular notPublic
-- where
--  notPublic :: SomeException -> IO ()
--  notPublic e =
--    do logMsg torState ("Couldn't build route to myself: " ++ show e)
--       logMsg torState "I hope this is an output-only, non-relay node."
--  --
--  tryCircular =
--    do logMsg torState "Getting initial router."
--       initRouter <- getRouter torState []
--       logMsg torState "Creating circuit."
--       circ       <- throwLeft =<< createCircuit torState initRouter
--       logMsg torState "Getting local address."
--       myAddrs    <- getLocalAddresses torState
--       logMsg torState ("My publicly-routable IP address(es): " ++
--                        intercalate "," (map show myAddrs))
--       logMsg torState "Getting intermediate router."
--       midRouter  <- getRouter torState [NotRouter initRouter]
--       logMsg torState ("Extending router to " ++ routerIPv4Address midRouter)
--       ()         <- throwLeft =<< extendCircuit torState circ midRouter
--       lastRouter <- getRouter torState [NotRouter initRouter,
--                                         NotRouter midRouter,
--                                         NotTorAddr (IP4 "37.49.35.221"),
--                                         NotTorAddr (IP4 "62.210.74.143"),
--                                         NotTorAddr (IP4 "162.248.160.151"),
--                                         NotTorAddr (IP4 "109.235.50.163"),
--                                         ExitNodeAllowing (IP4 "66.193.37.213") 80]
--       logMsg torState ("Extending router to " ++ routerIPv4Address lastRouter)
--       ()         <- throwLeft =<< extendCircuit torState circ lastRouter
--       nms        <- resolveName circ "galois.com"
--       logMsg torState ("Resolved galois.com to " ++ show nms)
--       logMsg torState ("Exit rules: " ++ show (routerExitRules lastRouter))
--       con        <- connectToHost circ (Hostname "uhsure.com") 80
--       logMsg torState ("Built connection!")
--       torWrite con (buildGet "http://uhsure.com/")
--       logMsg torState ("Wrote GET")
--       resp <- torRead con 300
--       logMsg torState ("Got response: " ++ show resp)
--       destroyCircuit circ NoReason
--  --
--  buildGet str = result
--   where
--    result      = BSC.pack (requestLine ++ userAgent ++ crlf)
--    requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
--    userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
--    crlf        = "\r\n"
--
--
--startTorServerPort :: HasBackend sock => TorState lsock sock -> Word16 -> IO ()
--startTorServerPort torState onionPort =
--  do let ns = getNetworkStack torState
--     lsock <- listen ns onionPort
--     logMsg torState ("Waiting for Tor connections on port " ++ show onionPort)
--     forkIO_ $ forever $ do (sock, addr) <- accept ns lsock
--                            forkIO_ (acceptIncomingLink torState sock addr)
--     return ()
--
-- -----------------------------------------------------------------------------

initializeSystem :: [Flag] ->
                    IO (SomeNetworkStack, String -> IO ())
#ifdef HaLVM_HOST_OS
initializeSystem _ =
  do con    <- initXenConsole
     xs     <- initXenStore
     ns     <- newNetworkStack
     macstr <- findNIC xs
     nic    <- openNIC xs macstr
     let mac = read macstr
     addDevice ns mac (xenSend nic) (xenReceiveLoop nic)
     deviceUp ns mac
     ipaddr <- dhcpDiscover ns mac
     return (MkNS (hansNetworkStack ns), makeLogger (\ x -> writeConsole con (x ++ "\n")))
 where
  findNIC xs =
    do nics <- listNICs xs
       case nics of
         []    -> threadDelay 1000000 >> findNIC xs
         (x:_) -> return x
#else
initializeSystem flags =
  case getTapDevice flags of
    Nothing ->
      do logger <- generateLogger flags
         return (MkNS systemNetworkStack, logger)
    Just tapName ->
      do mfd <- openTapDevice tapName
         case mfd of
           Nothing ->
             fail ("Couldn't open tap device " ++ tapName)
           Just fd ->
             do ns <- newNetworkStack
                logger <- generateLogger flags
                let mac = read "52:54:00:12:34:56"
                addDevice ns mac (tapSend fd) (tapReceiveLoop fd)
                deviceUp ns mac
                ipaddr <- dhcpDiscover ns mac
                logger ("Node has IP Address " ++ show ipaddr)
                return (MkNS (hansNetworkStack ns), logger)

generateLogger :: [Flag] -> IO (String -> IO ())
generateLogger []                 = return (makeLogger (hPutStrLn stdout))
generateLogger ((OutputLog fp):_) = do h <- openFile fp AppendMode
                                       return (makeLogger (hPutStrLn h))
generateLogger (_:rest)           = generateLogger rest
#endif

-- -----------------------------------------------------------------------------

throwLeft :: Either String b -> IO b
throwLeft (Left s)  = fail s
throwLeft (Right x) = return x

forkIO_ :: IO () -> IO ()
forkIO_ m = forkIO m >> return ()
