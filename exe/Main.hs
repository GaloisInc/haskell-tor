{-# LANGUAGE CPP              #-}
{-# LANGUAGE RecordWildCards  #-}
import Data.ByteString.Char8(ByteString,pack)
import qualified Data.ByteString.Lazy as L
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

import qualified Data.ByteString as S
import Tor.Link
import Tor.Circuit
import Tor.State.Credentials
import Control.Concurrent
import Crypto.Random
import Tor.RouterDesc
import Tor.DataFormat.Helpers
import Tor.State.Directories
import Tor.State.Routers

--main :: IO ()
--main = runDefaultMain $ \ flags ->
--  do rngMV <- newMVar =<< drgNew
--     addrsMV <- newMVar []
--     (MkNS ns, logger) <- initializeSystem flags
----      dirdb <- newDirectoryDatabase ns logger
----      db <- newRouterDatabase ns dirdb logger
--     creds <- newCredentials logger
--     [_,printAscii] <- words `fmap` readFile "/Users/awick/.tor/fingerprint"
--     keyfile <- S.readFile "/Users/awick/.tor/keys/secret_onion_key_ntor"
--     let target = blankRouterDesc { routerIPv4Address  = "10.0.1.27"
--                                  , routerORPort       = 9001
--                                  , routerFingerprint  = readHex printAscii
--                                  , routerNTorOnionKey = Just (S.drop 64 keyfile)
--                                  }
----     second <- modifyMVar rngMV (getRouter db [])
----     third <- modifyMVar rngMV (getRouter db [])
--     link <- initLink ns creds rngMV addrsMV logger target
--     circId <- modifyMVar rngMV (linkNewCircuitId link)
--     circ <- createCircuit rngMV logger link target circId
----     extendCircuit circ second
----     putStrLn "Done."
----     extendCircuit circ third
----     putStrLn "Done."
--     foo <- resolveName circ "galois.com"
--     putStrLn ("Foo: " ++ show foo)

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
     addrs <- torResolveName tor "www.whatismypublicip.com"
     case addrs of
       [] ->
         putStrLn ("Could not resolve www.whatismypublicip.com!")
       ((addr, _ttl) : _) ->
         do sock <- torConnect tor addr 80
            putStrLn ("Connected to " ++ show addr)
            torWrite sock (buildGet "http://uhsure.com/")
            putStrLn ("Wrote GET request.")
            resp <- readLoop sock
            putStrLn ("Response: " ++ show resp)
            torClose sock ReasonDone

buildGet :: String -> ByteString
buildGet str = result
 where
  result      = pack (requestLine ++ userAgent ++ crlf)
  requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
  userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
  crlf        = "\r\n"

readLoop :: TorSocket -> IO L.ByteString
readLoop sock =
  do next <- torRead sock 256
     if L.length next < 256
        then return next
        else do putStrLn ("Read chunk: " ++ show next)
                rest <- readLoop sock
                return (next `L.append` rest)

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
