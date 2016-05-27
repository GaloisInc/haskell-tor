module Test.Network.ByteChan(
         ByteChan
       , newByteChan
       , readByteChan
       , writeByteChan
       , isEmptyByteChan
       , testByteChan
       )
 where

import           Control.Concurrent.MVar(MVar, newMVar, modifyMVar, modifyMVar_)
import           Control.Concurrent.MVar(withMVar)
import           Control.Monad(replicateM)
import           Data.ByteString(ByteString)
import qualified Data.ByteString as S
import           Data.Sequence(Seq, (<|), (|>), ViewL(..), viewl)
import qualified Data.Sequence as Seq
import           System.Timeout(timeout)
import           Test.Framework(Test, testGroup)
import           Test.Framework.Providers.QuickCheck2(testProperty)
import           Test.QuickCheck(Property)
import           Test.QuickCheck.Monadic(PropertyM, monadicIO, pre, run, assert)
import           Test.Standard()

newtype ByteChan = BC (MVar (Seq ByteString))

newByteChan :: IO ByteChan
newByteChan = BC `fmap` newMVar Seq.empty

readByteChan :: ByteChan -> Int -> IO ByteString
readByteChan bc@(BC seqMV) amt =
  do bstr <- getSome
     let amt' = amt - fromIntegral (S.length bstr)
     if amt' == 0
        then return bstr
        else do rest <- readByteChan bc amt' -- FIXME: make this block
                return (bstr `S.append` rest)
 where
  getSome :: IO ByteString
  getSome = modifyMVar seqMV (yank amt)
  --
  yank :: Int -> Seq ByteString -> IO (Seq ByteString, ByteString)
  yank x s =
    case viewl s of
      EmptyL -> return (s, S.empty)
      bstr :< rest
        | x <  fromIntegral (S.length bstr) ->
           do let (res, ret) = S.splitAt (fromIntegral x) bstr
              return (ret <| rest, res)
        | x == fromIntegral (S.length bstr) ->
           return (rest, bstr)
        | otherwise ->
           do (ret, bstr') <- yank (x - fromIntegral (S.length bstr)) rest
              return (ret, bstr `S.append` bstr')

writeByteChan :: ByteChan -> ByteString -> IO ()
writeByteChan (BC seqMV) bstr =
  modifyMVar_ seqMV $ return . (|> bstr)

isEmptyByteChan :: ByteChan -> IO Bool
isEmptyByteChan (BC seqMV) =
  withMVar seqMV $ return . Seq.null

-- -----------------------------------------------------------------------------

testByteChan :: Test
testByteChan =
  testGroup "Byte Channel tests" [
    testProperty "ByteString out matches ByteString in" prop_inOutSimple
  , testProperty "Multiple ByteStrings transfer right" prop_inOutMultiple
  , testProperty "Out-of-order ByteString reads work" prop_inOutReverse
  , testProperty "Single-byte writes to big read" prop_inOutSingleWrite
  , testProperty "Single-byte reads from a big write" prop_inOutSingleRead
  ]

prop_inOutSimple :: ByteString -> Property
prop_inOutSimple bstr =
  monadicIO $ do let len = fromIntegral (S.length bstr)
                 pre (len > 0)
                 bchan <- run $ newByteChan
                 run $ writeByteChan bchan bstr
                 result <- run $ readByteChan bchan len
                 assert (result == bstr)

prop_inOutMultiple :: [ByteString] -> Property
prop_inOutMultiple bstrs =
  monadicIO $ do let everything = S.concat bstrs
                     lens       = map (fromIntegral . S.length) bstrs
                     lens'      = filter (/= 0) lens
                 bchan <- run newByteChan
                 run $ mapM_ (writeByteChan bchan) bstrs
                 result <- run $ mapM (readByteChan bchan) lens'
                 let result' = S.concat result
                 assert (everything == result')

prop_inOutReverse :: [ByteString] -> Property
prop_inOutReverse bstrs =
  monadicIO $ do let everything = S.concat bstrs
                     lens       = map (fromIntegral . S.length) bstrs
                     lens'      = reverse (filter (/= 0) lens)
                 bchan <- run newByteChan
                 run $ mapM_ (writeByteChan bchan) bstrs
                 result <- run $ mapM (readByteChan bchan) lens'
                 let result' = S.concat result
                 assert (everything == result')

prop_inOutSingleWrite :: ByteString -> Property
prop_inOutSingleWrite bstr =
  monadicIO $ do let len = fromIntegral (S.length bstr)
                 pre (len > 0)
                 let units = map S.singleton (S.unpack bstr)
                 bchan <- run newByteChan
                 run $ mapM_ (writeByteChan bchan) units
                 result <- runQuickly $ readByteChan bchan len
                 assert (result == bstr)

prop_inOutSingleRead :: ByteString -> Property
prop_inOutSingleRead bstr =
  monadicIO $ do let len = fromIntegral (S.length bstr)
                 pre (len > 0)
                 bchan <- run newByteChan
                 run $ writeByteChan bchan bstr
                 result <- runQuickly $ replicateM len (readByteChan bchan 1)
                 assert (S.concat result == bstr)

runQuickly :: IO a -> PropertyM IO a
runQuickly action =
  do result <- run $ timeout 5000000 action
     case result of
       Nothing -> assert False >> error "Weird situation in runQuickly"
       Just x  -> return x
