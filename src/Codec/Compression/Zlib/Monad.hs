module Codec.Compression.Zlib.Monad(
         DeflateM
       , runDeflateM
         -- * Getting data from the input stream.
       , nextBit
       , nextBits
       , nextByte
       , nextWord16
       , nextBlock
       , nextCode
       , readRest
         -- * Aligning
       , advanceToByte
         -- * Emitting data
       , emitByte
       , emitBlock
       , emitPastChunk
         -- * Getting output
       , finalAdler
       , finalOutput
       )
 where

import Codec.Compression.Zlib.Adler32
import Codec.Compression.Zlib.HuffmanTree
import Codec.Compression.Zlib.OutputWindow
import Control.Monad
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Int
import Data.Word
import MonadLib
import MonadLib.Monads

data DecompressState = DecompressState {
       dcsNextBitNo     :: Int
     , dcsCurByte       :: Word8
     , dcsAdler32       :: AdlerState
     , dcsInput         :: ByteString
     , dcsOutput        :: OutputWindow
     }

type DeflateM = State DecompressState

initialState :: ByteString -> DecompressState
initialState bstr =
  case BS.uncons bstr of
    Nothing       -> error "No compressed data to inflate."
    Just (f,rest) -> DecompressState 0 f initialAdlerState rest emptyWindow

runDeflateM :: Show a => DeflateM a -> ByteString -> a
runDeflateM m i = result
  where (result, _) = runState (initialState i) m

-- -----------------------------------------------------------------------------

nextBit :: DeflateM Bool
nextBit =
  do dcs <- get
     let v = dcsCurByte dcs `testBit` dcsNextBitNo dcs
     set $ advanceBit dcs
     return v
 where
  advanceBit dcs
    | dcsNextBitNo dcs == 7 =
        case BS.uncons (dcsInput dcs) of
          Nothing ->
            error "Bit required, but no bits available!"
          Just (nextb, rest) ->
            dcs{ dcsNextBitNo = 0, dcsCurByte = nextb, dcsInput = rest }
    | otherwise             =
        dcs{ dcsNextBitNo = dcsNextBitNo dcs + 1 }

nextBits :: (Num a, Bits a) => Int -> DeflateM a
nextBits x
 | x < 1     = error "nextBits called with x < 1"
 | x == 1    = toNum `fmap` nextBit
 | otherwise = do cur  <- toNum `fmap` nextBit
                  rest <- nextBits (x - 1)
                  return ((rest `shiftL` 1) .|. cur)
 where
  toNum False = 0
  toNum True  = 1

nextByte :: DeflateM Word8
nextByte =
  do dcs <- get
     case BS.uncons (dcsInput dcs) of
       _ | dcsNextBitNo dcs /= 0 ->
            nextBits 8
       Nothing ->
         error "nextByte called with no more data."
       Just (nextb, rest) ->
          do set dcs{ dcsNextBitNo = 0, dcsCurByte = nextb, dcsInput = rest }
             return (dcsCurByte dcs)

nextWord16 :: DeflateM Word16
nextWord16 =
  do high <- fromIntegral `fmap` nextByte
     low  <- fromIntegral `fmap` nextByte
     return ((high `shiftL` 8) .|. low)

nextBlock :: Integral a => a -> DeflateM ByteString
nextBlock amt =
  do dcs <- get
     unless (dcsNextBitNo dcs == 0) $
       fail "Can't get a block on a non-byte boundary."
     let curBlock = BS.cons (dcsCurByte dcs) (dcsInput dcs)
         (block, rest) = BS.splitAt (fromIntegral amt) curBlock
     case BS.uncons rest of
       Nothing ->
         fail "Not enough data left after nextBlock."
       Just (first, rest') ->
         do set dcs{ dcsNextBitNo = 0, dcsCurByte = first, dcsInput = rest' }
            return block

nextCode :: Show a => HuffmanTree a -> DeflateM a
nextCode tree =
  do b <- nextBit
     case advanceTree b tree of
       Left tree' -> nextCode tree'
       Right x    -> return x

readRest :: DeflateM ByteString
readRest =
  do dcs <- get
     return (BS.cons (dcsCurByte dcs) (dcsInput dcs))

advanceToByte :: DeflateM ()
advanceToByte =
  do dcs <- get
     when (dcsNextBitNo dcs /= 0) $
       case BS.uncons (dcsInput dcs) of
         Nothing -> error "Advanced with no bytes left!"
         Just (nextb, rest) ->
           set dcs{ dcsNextBitNo = 0, dcsCurByte = nextb, dcsInput = rest }

emitByte :: Word8 -> DeflateM ()
emitByte b =
  do dcs <- get
     set dcs{ dcsOutput  = dcsOutput dcs `addByte` b
            , dcsAdler32 = advanceAdler (dcsAdler32 dcs) b }

emitBlock :: ByteString -> DeflateM ()
emitBlock b =
  do dcs <- get
     set dcs { dcsOutput  = dcsOutput dcs `addChunk` b
             , dcsAdler32 = BS.foldl advanceAdler (dcsAdler32 dcs) b }

emitPastChunk :: Int -> Int64 -> DeflateM ()
emitPastChunk dist len =
  do dcs <- get
     let (output', newChunk) = addOldChunk (dcsOutput dcs) dist len
     set dcs { dcsOutput = output'
             , dcsAdler32 = BS.foldl advanceAdler (dcsAdler32 dcs) newChunk }

finalAdler :: DeflateM Word32
finalAdler = (finalizeAdler . dcsAdler32) `fmap` get

finalOutput :: DeflateM ByteString
finalOutput = (outByteString . dcsOutput) `fmap` get

