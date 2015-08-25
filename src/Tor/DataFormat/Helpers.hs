{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.DataFormat.Helpers(
         PortSpec(..)
       , AddrSpec(..)
       , standardLine
       , nickname
       , hexDigest
       , port
       , addrSpec
       , portSpec
       , ip4
       , ip6
       , publicKey, publicKey'
       , utcTime
       --
       , bool
       , char8
       , alphaNum
       , decDigit
       , hexDigit
       , base64Char
       , decimalNum
       , whitespace, whitespace1
       , sp
       , nl, newline
       --
       , toString
       , readHex
       , decodeBase64
       )
 where

import Control.Applicative
import Crypto.PubKey.RSA
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.Attoparsec.ByteString
import Data.ByteString.Char8(pack)
import Data.ByteString.Base64
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Char hiding (isHexDigit, isAlphaNum)
import Data.Hourglass
import Data.Word
import Tor.RouterDesc

standardLine :: String -> Parser a -> Parser a
standardLine thing parser =
  do _ <- string (pack thing)
     _ <- sp
     x <- parser
     _ <- nl
     return x

nickname :: Parser String
nickname =
  do first <- alphaNum
     toString <$> run 1 [first]
  <?> "nickname"
 where
  run :: Int -> [Word8] -> Parser [Word8]
  run 20 acc = return (reverse acc)
  run x  acc =
    do next <- option Nothing (Just <$> alphaNum)
       case next of
         Nothing  -> return (reverse acc)
         Just c   -> run (x + 1) (c : acc)

hexDigest :: Parser ByteString
hexDigest = (readHex . toString) <$> count 40 hexDigit

portSpec :: Parser PortSpec
portSpec = choice [ allPorts, somePorts, onePort ] <?> "portSpec"
 where
  allPorts =
    do _ <- char8 '*'
       return PortSpecAll
  somePorts =
    do p1 <- port False
       _  <- char8 '-'
       p2 <- port False
       return (PortSpecRange p1 p2)
  onePort =
    do p <- port False
       return (PortSpecSingle p)

port :: Bool -> Parser Word16
port zeroOK =
  do base <- toString <$> many1 decDigit
     let result = read base :: Integer
     if | (result >= 1) && (result <= 65535) -> return (fromIntegral result)
        | zeroOK        &&  result == 0      -> return 0
        | otherwise                          -> empty
  <?> "port"

addrSpec :: Parser AddrSpec 
addrSpec = choice [ allAddrs, ip4Addrs, ip6Addrs ]
 where
  allAddrs  = char8 '*' >> return AddrSpecAll
  ip4Addrs  = choice [ip4Mask, ip4Bits, ip4Single]
  ip6Addrs  = choice [ip6Bits, ip6Single]
  ip4Mask   = do a <- ip4
                 _ <- char8 '/'
                 b <- ip4mask
                 return (AddrSpecIP4Mask a b)
  ip4Bits   = do a <- ip4
                 _ <- char8 '/'
                 b <- num_ip4_bits
                 return (AddrSpecIP4Bits a b)
  ip4Single = AddrSpecIP4 <$> ip4
  ip6Bits   = do a <- ip6
                 _ <- char8 '/'
                 b <- num_ip6_bits
                 return (AddrSpecIP6Bits a b)
  ip6Single = AddrSpecIP6 <$> ip6
  --
  ip4mask   = ip4
  --
  num_ip4_bits = decimalNum (<= 32)
  num_ip6_bits = decimalNum (<= 128)

ip4 :: Parser String
ip4 =
  do a <- decimalNum ip4num
     _ <- char8 '.'
     b <- decimalNum ip4num
     _ <- char8 '.'
     c <- decimalNum ip4num
     _ <- char8 '.'
     d <- decimalNum ip4num
     return (show a ++ "." ++ show b ++ "." ++ show c ++ "." ++ show d)
 where
  ip4num :: Int -> Bool
  ip4num x = x < 256

ip6 :: Parser String
ip6 = do
  _ <- char8 '[' -- FIXME: This parser is terrible
  a <- many1 (satisfy (\ x -> isHexDigit x || x == 58))
  _ <- char8 ']'
  return (toString a)

publicKey' :: Parser (PublicKey, ByteString)
publicKey' =
  do _ <- string "-----BEGIN RSA PUBLIC KEY-----\n"
     let end = string "-----END RSA PUBLIC KEY-----\n"
     bstr <- decodeBase64 =<< manyTill base64Char end
     case decodeASN1' DER bstr of
       Left  _    -> empty
       Right asn1 ->
         case fromASN1' asn1 of
           Left  _ -> empty
           Right x -> return (x, bstr)
 where
  fromASN1' (Start Sequence : IntVal n : IntVal e : End Sequence : _) =
    Right (PublicKey { public_size = calculate_modulus n 1
                     , public_n    = n
                     , public_e    = e
                     })
  fromASN1' _ = Left ("fromASN1: RSA PublicKey: unexpected format" :: String)
  --
  calculate_modulus n i =
    if (2 ^ (i * 8)) > n then i else calculate_modulus n (i + 1)

publicKey :: Parser PublicKey
publicKey = fst <$> publicKey'

utcTime :: Parser DateTime
utcTime =
  do dateYear  <- toEnum' `fmap` count 4 decDigit
     _         <- char8 '-'
     dateMonth <- toEnum' `fmap` count 2 decDigit
     _         <- char8 '-'
     dateDay   <- toEnum' `fmap` count 2 decDigit
     _         <- char8 ' '
     todHour   <- toEnum' `fmap` count 2 decDigit
     _         <- char8 ':'
     todMin    <- toEnum' `fmap` count 2 decDigit
     _         <- char8 ':'
     todSec    <- toEnum' `fmap` count 2 decDigit
     let todNSec = 0
         dtDate = Date { .. }
         dtTime = TimeOfDay { .. }
     return DateTime{..}
 where
  toEnum' :: Enum a => [Word8] -> a
  toEnum' = toEnum . read . BSC.unpack . BS.pack

-- ----------------------------------------------------------------------------

bool :: Parser Bool
bool = choice [ true, false ]
 where
  true  = char8 '1' >> return True
  false = char8 '0' >> return False

char8 :: Char -> Parser Word8
char8 c = word8 (fromIntegral (ord c))

alphaNum :: Parser Word8
alphaNum = satisfy isAlphaNum

isAlphaNum :: Word8 -> Bool
isAlphaNum = inClass (['A'..'Z']++['a'..'z']++['0'..'9'])

hexDigit :: Parser Word8
hexDigit = satisfy isHexDigit

isHexDigit :: Word8 -> Bool
isHexDigit = inClass (['0'..'9']++['a'..'f']++['A'..'F'])

decDigit :: Parser Word8
decDigit = satisfy isDecimalDigit

isDecimalDigit :: Word8 -> Bool
isDecimalDigit = inClass ['0'..'9']

base64Char :: Parser Word8
base64Char = satisfy isBase64Char

isBase64Char :: Word8 -> Bool
isBase64Char x = isAlphaNum x || (x == 10) || inClass "/+=" x

decimalNum :: (Integral a, Read a) => (a -> Bool) -> Parser a
decimalNum isOK =
  do n <- many1 decDigit
     case reads (toString n) of
       [(x, "")] | isOK x -> return x
       _                  -> empty

whitespace :: Parser ()
whitespace = many (satisfy (inClass " \t")) >> return () <?> "whitespace"

whitespace1 :: Parser ()
whitespace1 = many1 (satisfy (inClass " \t")) >> return ()

newline :: Parser ()
newline = whitespace >> word8 10 >> return ()

sp :: Parser Word8
sp = char8 ' '

nl :: Parser Word8
nl = char8 '\n'

-- ----------------------------------------------------------------------------

toString :: [Word8] -> String
toString = map (chr . fromIntegral)

readHex :: String -> ByteString
readHex []  = BS.empty
readHex [_] = error "Attempted to readHex an odd-lengthed string."
readHex (a:b:rest) = 
  let x = fromIntegral ((digitToInt a * 16) + digitToInt b)
  in BS.cons x (readHex rest)

decodeBase64 :: [Word8] -> Parser ByteString
decodeBase64 bytes =
  case decode (BS.pack (filter (/= 10) bytes)) of
    Left _    -> empty
    Right res -> return res
