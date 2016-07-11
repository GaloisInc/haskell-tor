module Test.Network.ByteChan(
         ByteChan
       , newByteChan
       , readByteChan
       , writeByteChan
       , isEmptyByteChan
       , testByteChan
       )
 where

import           Control.Concurrent(forkIO)
import           Control.Concurrent.Chan(Chan, newChan, readChan, writeChan)
import           Control.Concurrent.MVar(MVar, newEmptyMVar, takeMVar,tryPutMVar)
import           Control.Exception(SomeException, BlockedIndefinitelyOnMVar(..))
import           Control.Exception(Exception(fromException), handle)
import           Control.Monad(replicateM)
import           Data.ByteString(ByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           System.Timeout(timeout)
import           Test.Framework(Test, testGroup)
import           Test.Framework.Providers.QuickCheck2(testProperty)
import           Test.QuickCheck(Property)
import           Test.QuickCheck.Monadic(PropertyM, monadicIO, pre, run, assert)
import           Test.Standard()

newtype ByteChan = BC (Chan Request)

data Request = Write   ByteString (MVar ())
             | Read    Int        (MVar ByteString)
             | IsEmpty            (MVar Bool)

instance Show Request where
  show (Write bstr _) = "WRITE(" ++ show (S.length bstr) ++ ")"
  show (Read  amt  _) = "READ(" ++ show amt ++ ")"
  show (IsEmpty    _) = "ISEMPTY"

newByteChan :: IO ByteChan
newByteChan =
  do chan <- newChan
     _    <- forkIO (handle handleFail (runChannel L.empty [] chan))
     return (BC chan)
 where
  runChannel dataStream readers chan =
    do req <- readChan chan
       case req of
         Write bstr doneMV ->
           do let dataStream' = dataStream `L.append` (L.fromStrict bstr)
              (readers', dataStream'') <- processWaiters readers dataStream'
              _ <- tryPutMVar doneMV ()
              runChannel dataStream'' readers' chan
         Read amt resMV  ->
           do let readers' = readers ++ [(amt, resMV)]
              (readers'', dataStream') <- processWaiters readers' dataStream
              runChannel dataStream' readers'' chan
         IsEmpty resMV ->
           do _ <- tryPutMVar resMV (L.null dataStream)
              runChannel dataStream readers chan
  --
  processWaiters [] strm = return ([], strm)
  processWaiters readers@((amt, resMV) : rest) strm
    | fromIntegral amt <= L.length strm =
        do let (mine, strm') = L.splitAt (fromIntegral amt) strm
           _ <- tryPutMVar resMV (L.toStrict mine)
           processWaiters rest strm'
    | otherwise =
        return (readers, strm)
  --
  handleFail :: SomeException -> IO ()
  handleFail e =
    case fromException e of
      Just BlockedIndefinitelyOnMVar ->
        return () -- How we fail
      _ ->
        do putStrLn ("HANDLE_FAIL: " ++ (show e))
           fail "Failed running byte channel thread!"

readByteChan :: ByteChan -> Int -> IO ByteString
readByteChan _         0   =
  return S.empty
readByteChan (BC chan) amt =
  do resMV <- newEmptyMVar
     writeChan chan (Read amt resMV)
     takeMVar resMV

writeByteChan :: ByteChan -> ByteString -> IO ()
writeByteChan (BC chan) bstr =
  do resMV <- newEmptyMVar
     writeChan chan (Write bstr resMV)
     takeMVar resMV

isEmptyByteChan :: ByteChan -> IO Bool
isEmptyByteChan (BC chan) =
  do resMV <- newEmptyMVar
     writeChan chan (IsEmpty resMV)
     takeMVar resMV

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
