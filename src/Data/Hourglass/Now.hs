-- |A helper module, which will likely evenutally be removable.
{-# LANGUAGE RecordWildCards   #-}
module Data.Hourglass.Now(getCurrentTime)
 where

import Data.Hourglass
import Data.Hourglass.Compat
import qualified Data.Time as T

-- |Fetch the current date, and return it as a DateTime.
getCurrentTime :: IO DateTime
getCurrentTime =
  do now <- T.getCurrentTime
     let dtDate = dateFromTAIEpoch (T.toModifiedJulianDay (T.utctDay now))
         dtTime = diffTimeToTimeOfDay (T.utctDayTime now)
     return DateTime{..}


