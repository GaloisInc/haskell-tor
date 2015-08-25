module Tor.RNG(TorRNG) where

import Crypto.Random

type TorRNG = ChaChaDRG
