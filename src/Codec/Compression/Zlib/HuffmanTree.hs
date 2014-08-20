module Codec.Compression.Zlib.HuffmanTree(
         HuffmanTree
       , createHuffmanTree
       , advanceTree
       )
 where

import Data.Bits

data HuffmanTree a = HuffmanNode (HuffmanTree a) (HuffmanTree a)
                   | HuffmanValue a
                   | HuffmanEmpty
 deriving (Show)

emptyHuffmanTree :: HuffmanTree a
emptyHuffmanTree = HuffmanEmpty

createHuffmanTree :: Show a => [(a, Int, Int)] -> HuffmanTree a
createHuffmanTree = foldr addHuffmanNode' emptyHuffmanTree
 where addHuffmanNode' (a, b, c) = addHuffmanNode a b c

addHuffmanNode :: Show a => a -> Int -> Int -> HuffmanTree a -> HuffmanTree a
addHuffmanNode val 0   _    (HuffmanNode _ _) =
  error ("Tried to add where the leaf is a node: " ++ show val)
addHuffmanNode _   0   _    (HuffmanValue _) =
  error "Two values point to the same place!"
addHuffmanNode val 0   _    HuffmanEmpty =
  HuffmanValue val
addHuffmanNode val len code (HuffmanNode l r)
  | testBit code (len - 1) = HuffmanNode l (addHuffmanNode val (len - 1) code r)
  | otherwise              = HuffmanNode (addHuffmanNode val (len - 1) code l) r
addHuffmanNode _   _   _    (HuffmanValue _) =
  error "HuffmanValue hit while inserting a value!"
addHuffmanNode val len code HuffmanEmpty =
  let newNode = addHuffmanNode val (len - 1) code HuffmanEmpty
  in if testBit code (len - 1)
        then HuffmanNode HuffmanEmpty newNode
        else HuffmanNode newNode      HuffmanEmpty

advanceTree :: Bool -> HuffmanTree a -> Either (HuffmanTree a) a
advanceTree _ HuffmanEmpty     = error "Tried to advance empty tree!"
advanceTree _ (HuffmanValue _) = error "Tried to advance empty value!"
advanceTree x (HuffmanNode l r) =
  case if x then r else l of
    HuffmanEmpty   -> error "Advanced to empty tree!"
    HuffmanValue y -> Right y
    t              -> Left t

