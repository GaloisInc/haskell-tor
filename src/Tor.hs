{-# LANGUAGE ExistentialQuantification #-}
module Tor(
         -- * Setup and initialization
         SetupOptions(..)
       , ExitRule(..)
       , TorNetworkStack(..)
       , defaultTorOptions
       , Tor
       , startTor
         -- * Functions for Tor entrnce nodes
       , ConnectionOptions(..)
       , resolveName
       , connect
       , close
       , writeBS
       , readBS
       )
 where

import Data.ByteString(ByteString)
import Data.Word
import Tor.NetworkStack hiding (connect)
import Tor.RouterDesc
import Tor.State

type HostName = String

-- |How the node should be set up during initialization.
data SetupOptions =
    -- |This node should act as an entrance node. If you do not
    -- specify this, functions like resolveName and connect will
    -- not run. On the other hand, if you really don't plan to build any
    -- connections using this node, not including Entrance capabilities will
    -- make things start faster.
    TorEntrance
  | -- |This node should act as a Tor relay node.
     TorRelay {
      torOnionPort :: Maybe Word16 -- ^Default: 9374
    , torNickname  :: Maybe String -- ^Nickname for this node.
                                   -- Default: "haskell-tor"
    , torContact   :: Maybe String -- ^Default: unknown@unknown
    }
  | -- |This node should act as an exit node.
    TorExit {
      torExitRules :: [ExitRule]
    }
  | -- |Combine some set of the above.
    And SetupOptions SetupOptions

-- |A reasonable default set of options, which allows this node to be used as an
-- entrance and relay node.
defaultTorOptions :: SetupOptions
defaultTorOptions = TorEntrance `And` TorRelay Nothing Nothing Nothing

-- |A handle to the current Tor system state.
data Tor = forall ls s . Tor { unTor :: TorState ls s }

-- |Start up the underlying Tor system, given a network stack to operate in and
-- some setup options.
startTor :: TorNetworkStack ls s -> SetupOptions -> IO Tor
startTor = undefined

-- -----------------------------------------------------------------------------

resolveName :: Tor -> HostName -> IO Int
resolveName = undefined

data ConnectionOptions = None

data TorSocket = TorSocket

connect :: Tor -> ConnectionOptions -> HostName -> Word16 -> IO TorSocket
connect = undefined

writeBS :: TorSocket -> ByteString -> IO ()
writeBS = undefined

readBS :: TorSocket -> Int -> IO ByteString
readBS = undefined
