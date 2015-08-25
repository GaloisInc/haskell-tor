{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Tor.NetworkStack.Fetch(
         FetchItem(..)
       , fetch
       )
 where

import Codec.Compression.Zlib
import Control.Exception
import Crypto.Hash.Easy
import Crypto.PubKey.RSA.KeyHash
import Data.Attoparsec.ByteString
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Lazy.Char8(pack)
import Data.Either
import Data.Map(Map)
import qualified Data.Map as Map
import Data.Word
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

instance Show FetchItem where
  show ConsensusDocument = "/tor/status-vote/current/consensus.z"
  show KeyCertificate    = "/tor/keys/authority.z"
  show Descriptors       = "/tor/server/all.z"

fetch :: Fetchable a => 
         TorNetworkStack ls s ->
         String -> Word16 -> FetchItem ->
         IO (Either String a)
fetch ns host tcpport item =
  handle (\ err -> return (Left (show (err :: IOException)))) $
    do msock <- connect ns host tcpport
       case msock of
         Nothing -> return (Left "Connection failure.")
         Just sock ->
           do write ns sock (buildGet (show item))
              resp <- readResponse ns sock
              case resp of
                Left err   -> return (Left err)
                Right body ->
                  case decompress (L.fromStrict body) of
                    Nothing    -> return (Left "Decompression failure.")
                    Just body' -> return (parseBlob (L.toStrict body'))

buildGet :: String -> L.ByteString
buildGet str = result
 where
  result      = pack (requestLine ++ userAgent ++ crlf)
  requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
  userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
  crlf        = "\r\n"

readResponse :: TorNetworkStack ls s -> s -> IO (Either String ByteString)
readResponse ns sock = finally getResponse (close ns sock)
 where
  getResponse =
    do response <- recvAll ns sock
       case parse httpResponse (L.toStrict response) of
         Partial f ->
           handleParseResult (f BS.empty)
         x ->
           handleParseResult x
  --
  handleParseResult (Fail bstr _ err) =
    do let start = show (BS.take 10 bstr)
           msg = "Parser error: " ++ err ++ " [" ++ start ++ "]"
       return (Left msg)
  handleParseResult (Partial _) =
    return (Left "Partial response received from other side.")
  handleParseResult (Done _ res) =
    return res

httpResponse :: Parser (Either String ByteString)
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
        then return (Left ("HTTP Error: " ++ msg))
        else do _   <- many1 keyval
                _   <- crlf
                Right `fmap` takeByteString
 where
  crlf = char8 '\r' >> char8 '\n'
  keyval =
    do _ <- many1 (notWord8 13)
       _ <- crlf
       return ()

