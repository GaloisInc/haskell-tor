{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Tor.NetworkStack.Fetch(
         FetchItem(..)
       , Fetchable
       , fetch
       )
 where

import Codec.Compression.Zlib
import Control.Exception
import Crypto.Hash.Easy
import Crypto.PubKey.RSA.KeyHash
import Data.Attoparsec.ByteString
import Data.ByteString(ByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Lazy.Char8(pack)
import Data.Either
import Data.Map(Map)
import qualified Data.Map as Map
import Data.Word
import System.IO.Unsafe
import System.Timeout
import Tor.DataFormat.Consensus
import Tor.DataFormat.DirCertInfo
import Tor.DataFormat.Helpers
import Tor.DataFormat.RouterDesc
import Tor.NetworkStack
import Tor.RouterDesc

class Fetchable a where
  parseBlob :: ByteString -> Either String a

instance Fetchable DirectoryCertInfo where
  parseBlob = parseDirectoryCertInfo

instance Fetchable (Consensus, ByteString, ByteString) where
  parseBlob = parseConsensusDocument

instance Fetchable (Map ByteString RouterDesc) where
  parseBlob bstr = Right (convertEntries Map.empty xs)
   where
    (_, xs) = partitionEithers (parseDirectory bstr)
    --
    convertEntries m []    = m
    convertEntries m (d:r) =
      convertEntries (Map.insert (keyHash' sha1 (routerSigningKey d)) d m) r

data FetchItem = ConsensusDocument
               | KeyCertificate
               | Descriptors
 deriving (Show)

fetchItemFile :: FetchItem -> String
fetchItemFile ConsensusDocument = "/tor/status-vote/current/consensus.z"
fetchItemFile KeyCertificate    = "/tor/keys/authority.z"
fetchItemFile Descriptors       = "/tor/server/all.z"

fetchItemTime :: FetchItem -> Int
fetchItemTime ConsensusDocument =     60 * 1000000
fetchItemTime KeyCertificate    =     5  * 1000000
fetchItemTime Descriptors       = 3 * 60 * 1000000

fetch :: Fetchable a => 
         TorNetworkStack ls s ->
         String -> Word16 -> FetchItem ->
         IO (Either String a)
fetch ns host tcpport item =
  handle (\ err -> return (Left (show (err :: SomeException)))) $
    timeout' (fetchItemTime item) $
      do msock <- connect ns host tcpport
         case msock of
           Nothing -> return (Left "Connection failure.")
           Just sock ->
             do write ns sock (buildGet (fetchItemFile item))
                resp <- readResponse ns sock
                case resp of
                  Left err   -> return (Left err)
                  Right body ->
                    case decompress body of
                      Nothing    -> return (Left "Decompression failure.")
                      Just body' -> return (parseBlob (L.toStrict body'))
            `finally` close ns sock
 where
  timeout' tm io =
    do res <- timeout tm io
       case res of
         Nothing -> return (Left "Fetch timed out.")
         Just x  -> return x

buildGet :: String -> L.ByteString
buildGet str = result
 where
  result      = pack (requestLine ++ userAgent ++ crlf)
  requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
  userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
  crlf        = "\r\n"

readResponse :: TorNetworkStack ls s -> s -> IO (Either String L.ByteString)
readResponse ns sock = getResponse (parse httpResponse)
 where
  getResponse parseStep =
    do chunk <- recv ns sock 4096
       case parseStep chunk of
         Fail bstr _ err ->
           do let start = show (S.take 10 bstr)
                  msg = "Parser error: " ++ err ++ " [" ++ start ++ "]"
              return (Left msg)
         Partial f ->
           getResponse f
         Done res () ->
           (Right . L.fromChunks . (res:)) `fmap` lazyRead
  --
  lazyRead :: IO [ByteString]
  lazyRead = unsafeInterleaveIO $ do chunk <- recv ns sock 4096
                                     if S.null chunk
                                        then return []
                                        else do rest <- lazyRead
                                                return (chunk : rest)

httpResponse :: Parser ()
httpResponse =
  do _   <- string "HTTP/"
     _   <- decDigit
     _   <- char8 '.'
     _   <- decDigit
     _   <- sp
     v   <- decimalNum (const True)
     _   <- sp
     msg <- toString `fmap` many1 (notWord8 13)
     _   <- crlf
     if v /= (200 :: Integer)
        then fail ("HTTP Error: " ++ msg)
        else do _   <- many1 keyval
                _   <- crlf
                return ()
 where
  crlf = char8 '\r' >> char8 '\n'
  keyval =
    do _ <- many1 (notWord8 13)
       _ <- crlf
       return ()

