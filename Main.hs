import Control.Concurrent(forkIO)
import Control.Monad
import Data.Time
import Data.Version hiding (Version)
import Data.Word
import Network.Socket hiding (recv)
import Network.Socket.ByteString.Lazy(sendAll, recv)
import System.Console.GetOpt
import System.Environment
import System.Exit
import System.IO
import System.Locale
import TLS.Context.Explicit

import Tor.NetworkStack.System
import Tor.State

import Paths_haskell_tor

data Flag = Version
          | Help
          | OnionPort Word16
          | OutputLog FilePath
 deriving (Eq)

options :: [OptDescr Flag]
options =
  [ Option ['v']     ["version"]    (NoArg Version)
                     "show the version number"
  , Option ['h','?'] ["help"]       (NoArg Help)
                     "show this message"
  , Option ['p']     ["onion-port"] (ReqArg (OnionPort . read) "PORT")
                     "Select what onion port to use. [default 9374]"
  , Option ['o']     ["output-log"] (ReqArg OutputLog "FILE")
                     "Select where to write log info. [default stdout]"
  ]

showHelpAndStop :: Bool -> IO ()
showHelpAndStop okgood =
  do putStrLn (usageInfo "Usage: haskell-tor [options]" options)
     exitWith (if okgood then ExitSuccess else (ExitFailure 2))

showVersionAndStop :: IO ()
showVersionAndStop =
  do putStrLn ("Haskell Tor Version " ++ showVersion version)
     exitWith ExitSuccess

-- -----------------------------------------------------------------------------

main :: IO ()
main =
  do args <- getArgs
     case getOpt Permute options args of
       (opts, [], [])
         | Version `elem` opts -> showVersionAndStop
         | Help    `elem` opts -> showHelpAndStop True
         | otherwise           -> runTorNode opts
       (_, _, _)               -> showHelpAndStop False

runTorNode :: [Flag] -> IO ()
runTorNode flags =
  do logger        <- generateLogger flags
     let onionPort =  getOnionPort flags
     torState      <- initializeTorState systemNetworkStack logger
     -- start the onion socket
     return ()

torServerPort :: TorState a b -> Word16 -> IO ()
torServerPort torState onionPort =
  do lsock <- socket AF_INET Stream defaultProtocol
     bind lsock (SockAddrInet (PortNum onionPort) iNADDR_ANY)
     listen lsock 3
     forever $ do (sock, addr) <- accept lsock
                  logMsg torState ("Accepted TCP connection from " ++ show addr)
                  forkIO (runServerConnection torState sock)

runServerConnection :: TorState a b -> Socket -> IO ()
runServerConnection torState sock =
  do undefined torState sock

toIOSystem :: Socket -> IOSystem
toIOSystem sock = IOSystem {
    ioRead  = recv sock . fromIntegral
  , ioWrite = sendAll sock
  , ioFlush = return ()
  }

-- -----------------------------------------------------------------------------

getOnionPort :: [Flag] -> Word16
getOnionPort []                      = 9374 -- http://xkcd.com/221/
getOnionPort ((OnionPort op) : _)    = op
getOnionPort (_              : rest) = getOnionPort rest

generateLogger :: [Flag] -> IO (String -> IO ())
generateLogger []                 = return (makeLogger stdout)
generateLogger ((OutputLog fp):_) = makeLogger `fmap` openFile fp AppendMode
generateLogger (_:rest)           = generateLogger rest

makeLogger :: Handle -> String -> IO ()
makeLogger h msg =
  do now <- getCurrentTime
     let tstr = formatTime defaultTimeLocale "[%d%b%Y %X] " now
     hPutStrLn h (tstr ++ msg)
