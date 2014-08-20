{-# LANGUAGE MultiWayIf #-}
module Codec.Compression.Zlib.Deflate(
         inflate
       , computeCodeValues
       )
 where

import Codec.Compression.Zlib.HuffmanTree
import Codec.Compression.Zlib.Monad
import Control.Monad
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Int
import Data.List
import Data.Map.Strict(Map)
import qualified Data.Map.Strict as Map
import Data.Word

inflate :: DeflateM (Maybe ByteString)
inflate =
  do isFinal <- inflateBlock
     if isFinal
        then do advanceToByte
                rest     <- readRest
                ourAdler <- finalAdler
                result   <- finalOutput
                let theirAdler = BS.foldl shiftAdd 0 rest
                if | BS.length rest /= 4    -> return Nothing
                   | theirAdler /= ourAdler -> return Nothing
                   | otherwise              -> return (Just result)
        else inflate
 where shiftAdd x y = (x `shiftL` 8) .|. fromIntegral y

inflateBlock :: DeflateM Bool
inflateBlock =
  do bfinal <- nextBit
     btype  <- nextBits 2
     case btype :: Word8 of
       0 -> -- no compression
         do advanceToByte
            len  <- nextWord16
            nlen <- nextWord16
            unless (len == complement nlen) $
              fail "Len/nlen mismatch in uncompressed block."
            emitBlock =<< nextBlock len
            return bfinal
       1 -> -- compressed with fixed Huffman codes
         do runInflate fixedLitTree fixedDistanceTree
            return bfinal
       2 -> -- compressed with dynamic Huffman codes
         do hlit  <- (257+) `fmap` nextBits 5
            hdist <- (1+)   `fmap` nextBits 5
            hclen <- (4+)   `fmap` nextBits 4
            codeLens <- replicateM hclen (nextBits 3)
            let codeLens' = zip codeLengthOrder codeLens
                codeTree  = computeHuffmanTree codeLens'
            lens <- getCodeLengths codeTree 0 (hlit + hdist) 0 Map.empty
            -- We do this as a big chunk and then split it up because the spec
            -- allows repeat codes to cross the hlit / hdist boundary. So now we
            -- need to pull off the hdist items.
            let (litlens, offdistlens) =
                    Map.partitionWithKey (\ k _ -> k < hlit) lens
                distlens = Map.mapKeys (\ k -> k - hlit) offdistlens
                litTree  = computeHuffmanTree (Map.toList litlens)
                distTree = computeHuffmanTree (Map.toList distlens)
            runInflate litTree distTree
            return bfinal
       _ -> -- reserved / error
         error ("Unacceptable BTYPE: " ++ show btype)
 where
  runInflate :: HuffmanTree Int -> HuffmanTree Int -> DeflateM ()
  runInflate litTree distTree =
    do code <- nextCode litTree
       if | code <  256 -> do emitByte (fromIntegral code)
                              runInflate litTree distTree
          | code == 256 -> return ()
          | code > 256  -> do len      <- getLength code
                              distCode <- nextCode distTree
                              dist     <- getDistance distCode
                              emitPastChunk dist len
                              runInflate litTree distTree

-- -----------------------------------------------------------------------------

getCodeLengths :: HuffmanTree Int ->
                  Int -> Int -> Int ->
                  Map Int Int ->
                  DeflateM (Map Int Int)
getCodeLengths tree n maxl prev acc
  | n >= maxl   = return acc
  | otherwise =
    do code <- nextCode tree
       if | code <= 15 ->
                getCodeLengths tree (n+1) maxl code (Map.insert n code acc)
          | code == 16 -> -- copy the previous code length 3 - 6 times
             do num <- (3+) `fmap` nextBits 2
                getCodeLengths tree (n+num) maxl prev (addNTimes n num prev acc)
          | code == 17 -> -- repeat a code length of 0 for 3 - 10 times
             do num <- (3+) `fmap` nextBits 3
                getCodeLengths tree (n+num) maxl 0    (addNTimes n num 0 acc)
          | code == 18 -> -- repeat a code length of 0 for 11 - 138 times
             do num <- (11+) `fmap` nextBits 7
                getCodeLengths tree (n+num) maxl 0    (addNTimes n num 0 acc)
 where
  addNTimes idx count val old =
    let idxs = take count [idx..]
        vals = replicate count val
    in Map.union old (Map.fromList (zip idxs vals))

-- -----------------------------------------------------------------------------

getLength :: Int -> DeflateM Int64
getLength c =
  case Map.lookup c getLengthMap of
    Nothing -> error ("getLength for bad code: " ++ show c)
    Just m  -> m

getLengthMap :: Map Int (DeflateM Int64)
getLengthMap = Map.fromList [
    (257, return 3)
  , (258, return 4)
  , (259, return 5)
  , (260, return 6)
  , (261, return 7)
  , (262, return 8)
  , (263, return 9)
  , (264, return 10)
  , (265, (+ 11)  `fmap` nextBits 1)
  , (266, (+ 13)  `fmap` nextBits 1)
  , (267, (+ 15)  `fmap` nextBits 1)
  , (268, (+ 17)  `fmap` nextBits 1)
  , (269, (+ 19)  `fmap` nextBits 2)
  , (270, (+ 23)  `fmap` nextBits 2)
  , (271, (+ 27)  `fmap` nextBits 2)
  , (272, (+ 31)  `fmap` nextBits 2)
  , (273, (+ 35)  `fmap` nextBits 3)
  , (274, (+ 43)  `fmap` nextBits 3)
  , (275, (+ 51)  `fmap` nextBits 3)
  , (276, (+ 59)  `fmap` nextBits 3)
  , (277, (+ 67)  `fmap` nextBits 4)
  , (278, (+ 83)  `fmap` nextBits 4)
  , (279, (+ 99)  `fmap` nextBits 4)
  , (280, (+ 115) `fmap` nextBits 4)
  , (281, (+ 131) `fmap` nextBits 5)
  , (282, (+ 163) `fmap` nextBits 5)
  , (283, (+ 195) `fmap` nextBits 5)
  , (284, (+ 227) `fmap` nextBits 5)
  , (285, return 258)
  ]

getDistance :: Int -> DeflateM Int
getDistance c =
  case Map.lookup c getDistanceMap of
    Nothing -> error ("getDistance for bad code: " ++ show c)
    Just m  -> m

getDistanceMap :: Map Int (DeflateM Int)
getDistanceMap = Map.fromList [
    (0,  return 1)
  , (1,  return 2)
  , (2,  return 3)
  , (3,  return 4)
  , (4,  (+ 5)     `fmap` nextBits 1)
  , (5,  (+ 7)     `fmap` nextBits 1)
  , (6,  (+ 9)     `fmap` nextBits 2)
  , (7,  (+ 13)    `fmap` nextBits 2)
  , (8,  (+ 17)    `fmap` nextBits 3)
  , (9,  (+ 25)    `fmap` nextBits 3)
  , (10, (+ 33)    `fmap` nextBits 4)
  , (11, (+ 49)    `fmap` nextBits 4)
  , (12, (+ 65)    `fmap` nextBits 5)
  , (13, (+ 97)    `fmap` nextBits 5)
  , (14, (+ 129)   `fmap` nextBits 6)
  , (15, (+ 193)   `fmap` nextBits 6)
  , (16, (+ 257)   `fmap` nextBits 7)
  , (17, (+ 385)   `fmap` nextBits 7)
  , (18, (+ 513)   `fmap` nextBits 8)
  , (19, (+ 769)   `fmap` nextBits 8)
  , (20, (+ 1025)  `fmap` nextBits 9)
  , (21, (+ 1537)  `fmap` nextBits 9)
  , (22, (+ 2049)  `fmap` nextBits 10)
  , (23, (+ 3073)  `fmap` nextBits 10)
  , (24, (+ 4097)  `fmap` nextBits 11)
  , (25, (+ 6145)  `fmap` nextBits 11)
  , (26, (+ 8193)  `fmap` nextBits 12)
  , (27, (+ 12289) `fmap` nextBits 12)
  , (28, (+ 16385) `fmap` nextBits 13)
  , (29, (+ 24577) `fmap` nextBits 13)
  ]

-- -----------------------------------------------------------------------------

fixedLitTree :: HuffmanTree Int
fixedLitTree = computeHuffmanTree
  ([(x, 8) | x <- [0   .. 143]] ++
   [(x, 9) | x <- [144 .. 255]] ++
   [(x, 7) | x <- [256 .. 279]] ++
   [(x, 8) | x <- [280 .. 287]])

fixedDistanceTree :: HuffmanTree Int
fixedDistanceTree = computeHuffmanTree [(x,5) | x <- [0..31]]

-- -----------------------------------------------------------------------------

computeHuffmanTree :: [(Int, Int)] -> HuffmanTree Int
computeHuffmanTree = createHuffmanTree . computeCodeValues

computeCodeValues :: Ord a => [(a, Int)] -> [(a, Int, Int)]
computeCodeValues vals = Map.foldrWithKey (\ v (l, c) a -> (v,l,c):a) [] codes
 where
  valsNo0s = filter (\ (_, b) -> (b /= 0)) vals
  valsSort = sortBy (\ (a,_) (b,_) -> compare a b) valsNo0s
  blCount  = foldr (\ (_,k) m -> Map.insertWith (+) k 1 m) Map.empty valsNo0s
  nextcode = step2 0 1 (Map.insert 0 0 Map.empty)
  lenTree  = Map.fromList valsSort
  codeTree = step3 (map fst valsSort) nextcode Map.empty
  maxBits  = maximum (map snd valsSort)
  codes    = Map.intersectionWith (,) lenTree codeTree
  --
  step2 code bits nc
    | bits > maxBits = nc
    | otherwise =
      let prevCount = Map.findWithDefault 0 (bits - 1) blCount
          code' = (code + prevCount) `shiftL` 1
      in step2 code' (bits + 1) (Map.insert bits code' nc) 
  --
  step3 [] _ ct = ct
  step3 (n:rest) nc ct =
    let len        = Map.findWithDefault 0 n lenTree
        Just ncLen = Map.lookup len nc
        ct'        = Map.insert n ncLen ct
        nc'        = Map.insert len (ncLen + 1) nc
    in if len == 0
          then step3 rest nc  ct
          else step3 rest nc' ct'

codeLengthOrder :: [Int]
codeLengthOrder =
  [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


