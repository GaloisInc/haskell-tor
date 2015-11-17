-- |RNG routines
module Tor.RNG(TorRNG) where

import Crypto.Random

-- |The current alias for random number generators within the Tor
-- implementation. Renamed here because we may want to change this in the
-- future.
type TorRNG = ChaChaDRG
