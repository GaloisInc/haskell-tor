module Tor.Options(
         Flag(..)
       , runDefaultMain
       --
       , getNickname
       , getOnionPort
       , getContactInfo
       , getTapDevice
       )
 where

import Data.Version hiding (Version)
import Data.Word
import System.Console.GetOpt
import System.Environment
import System.Exit
import Paths_haskell_tor

data Flag = Version
          | Help
          | OnionPort Word16
          | OutputLog FilePath
          | Nickname String
          | ContactInfo String
          | UseTapDevice String
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
  , Option ['n']     ["node-nickname"] (ReqArg Nickname "STR")
                     "An (optional) nickname for this Tor node."
  , Option ['c']     ["node-contact"] (ReqArg ContactInfo "STR")
                     "An (optional) contact for this Tor node."
  , Option ['t']     ["use-tap"] (ReqArg UseTapDevice "STR")
                     "Use a direct connection to a tap device."
  ]

showHelpAndStop :: Bool -> IO ()
showHelpAndStop okgood =
  do putStrLn (usageInfo "Usage: haskell-tor [options]" options)
     exitWith (if okgood then ExitSuccess else (ExitFailure 2))

showVersionAndStop :: IO ()
showVersionAndStop =
  do putStrLn ("Haskell Tor Version " ++ showVersion version)
     exitWith ExitSuccess

runDefaultMain :: ([Flag] -> IO ()) -> IO ()
runDefaultMain runNode =
  do args <- getArgs
     case getOpt Permute options args of
       (opts, [], [])
         | Version `elem` opts -> showVersionAndStop
         | Help    `elem` opts -> showHelpAndStop True
         | otherwise           -> runNode opts
       (_, _, _)               -> showHelpAndStop False

-- -----------------------------------------------------------------------------

getNickname :: [Flag] -> String
getNickname []                  = ""
getNickname (Nickname x : _)    = x
getNickname (_          : rest) = getNickname rest

getOnionPort :: [Flag] -> Word16
getOnionPort []                   = 9002 -- http://xkcd.com/221/
getOnionPort (OnionPort p : _)    = p
getOnionPort (_           : rest) = getOnionPort rest

getContactInfo :: [Flag] -> Maybe String
getContactInfo []                      = Nothing
getContactInfo (ContactInfo ci : _)    = Just ci
getContactInfo (_              : rest) = getContactInfo rest

getTapDevice :: [Flag] -> Maybe String
getTapDevice []                      = Nothing
getTapDevice (UseTapDevice t : _)    = Just t
getTapDevice (_              : rest) = getTapDevice rest

