module Tor.State.RNG(
         RNG
       , TorRNG
       , newRNGState
       , withRNG
       , withRNGSTM
       )
 where

import Control.Concurrent.STM
import Control.Exception
import Crypto.Random.DRBG
import Data.Tagged
import System.Entropy

type TorRNG = GenAutoReseed CtrDRBG HashDRBG

newtype RNG = RNG (TVar TorRNG)

newRNGState :: (String -> IO ()) -> IO RNG
newRNGState logMsg =
  do let seedAmt = genSeedLength :: Tagged TorRNG ByteLength
     entropy <- getEntropy (fromIntegral (unTagged seedAmt))
     case newGen entropy of
       Left err ->
         do logMsg ("Could not make RNG: " ++ show err)
            throwIO err
       Right g ->
         RNG `fmap` newTVarIO g

withRNG :: RNG -> (TorRNG -> (a, TorRNG)) -> IO a
withRNG (RNG gTV) f =
  atomically $
    do g <- readTVar gTV
       let (res, g') = f g
       writeTVar gTV g'
       return res

withRNGSTM :: RNG -> (TorRNG -> STM (a, TorRNG)) -> STM a
withRNGSTM (RNG gTV) f =
  do g <- readTVar gTV
     (res, g') <- f g
     writeTVar gTV g'
     return res

