module Tor.DataFormat.TorAddress(
         TorAddress(..),    putTorAddress,    getTorAddress
       , unTorAddress
       , torAddressByteString
       , ip4ToString, ip6ToString
       , putIP4String, putIP6String
       )
 where

import Control.Monad
import Data.Bits
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8(pack,unpack)
import Data.ByteString.Lazy(toStrict)
import Data.Binary.Get
import Data.Binary.Put
import Data.List(intercalate)
import Data.Word
import Numeric

data TorAddress = Hostname String
                | IP4 String
                | IP6 String
                | TransientError String
                | NontransientError String
 deriving (Eq, Ord, Show)

unTorAddress :: TorAddress -> String
unTorAddress (Hostname s) = s
unTorAddress (IP4 s) = s
unTorAddress (IP6 s) = s
unTorAddress _       = error "unTorAddress: invalid input."

getTorAddress :: Get TorAddress
getTorAddress =
  do atype <- getWord8
     len   <- getWord8
     value <- getByteString (fromIntegral len)
     case (atype, len) of
       (0x00, _)  -> return (Hostname (unpack value))
       (0x04, 4)  -> return (IP4 (ip4ToString value))
       (0x04, _)  -> return (TransientError "Bad length for IP4 address.")
       (0x06, 16) -> return (IP6 (ip6ToString value))
       (0x06, _)  -> return (TransientError "Bad length for IP6 address.")
       (0xF0, _)  -> return (TransientError "External transient error.")
       (0xF1, _)  -> return (NontransientError "External nontransient error.")
       (_,    _)  -> return (NontransientError ("Unknown address type: " ++ show atype))

ip4ToString :: ByteString -> String
ip4ToString bstr = intercalate "." (map show (BS.unpack bstr))

ip6ToString :: ByteString -> String
ip6ToString bstr = "[" ++ intercalate ":" (run (BS.unpack bstr)) ++ "]"
 where
  run :: [Word8] -> [String]
  run []         = []
  run [_]        = ["ERROR"]
  run (a:b:rest) =
    let a' = fromIntegral a :: Word16
        b' = fromIntegral b :: Word16
        v  = (a' `shiftL` 8) .|. b'
    in (showHex v "" : run rest)

putTorAddress :: TorAddress -> Put
putTorAddress (Hostname str) =
  do putWord8 0x00
     let bstr = pack str
     putWord8 (fromIntegral (BS.length bstr))
     putByteString bstr
putTorAddress (IP4 str) =
  do putWord8     0x04
     putWord8     4
     putIP4String str
putTorAddress (IP6 str) =
  do putWord8 0x06
     putWord8 16
     putIP6String str
putTorAddress (TransientError _) =
  do putWord8 0xF0
     putWord8 0
putTorAddress (NontransientError _) =
  do putWord8 0xF1
     putWord8 0

putIP4String :: String -> Put
putIP4String str = forM_ (unintercalate '.' str) (putWord8 . read)

putIP6String :: String -> Put
putIP6String str =
  do let str' = unwrapIP6 str
     forM_ (unintercalate ':' str') $ \ v ->
       case readHex v of
        []        -> fail "Couldn't read IP6 address component."
        ((x,_):_) -> putWord16be x

torAddressByteString :: TorAddress -> ByteString
torAddressByteString (IP4 x) = 
  toStrict (runPut (forM_ (unintercalate '.' x) (putWord8 . read)))
torAddressByteString (IP6 x) =
  toStrict $ runPut $ forM_ (unintercalate ':' (unwrapIP6 x)) $ \ v ->
    case readHex v of
      []        -> fail "Couldn't read IP6 addr component."
      ((w,_):_) -> putWord16be w
torAddressByteString _ = error "Can't turn error into bytestring."

unintercalate :: Char -> String -> [String]
unintercalate _ "" = []
unintercalate c str =
  let (first, rest) = span (/= c) str
  in first : (unintercalate c (drop 1 rest))

unwrapIP6 :: String -> String
unwrapIP6 ('[':rest) =
  case reverse rest of
    (']':rrest) -> reverse rrest
    _ -> error ("IPv6 not in wrapped format (2): [" ++ rest)
unwrapIP6 x          = error ("IPv6 not in wrapped format: " ++ x)
