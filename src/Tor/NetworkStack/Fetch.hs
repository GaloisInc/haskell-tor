{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Tor.NetworkStack.Fetch(
         FetchItem(..)
       , fetch
       )
 where

import Codec.Compression.Zlib
import Control.Exception
import Data.Attoparsec.ByteString.Lazy
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.ByteString.Lazy.Char8(pack)
import Data.Digest.Pure.SHA
import Data.Word
import Tor.DataFormat.Consensus
import Tor.DataFormat.DirCertInfo
import Tor.DataFormat.Helpers
import Tor.NetworkStack

class Fetchable a where
  parseBlob :: ByteString -> Either String a

instance Fetchable DirectoryCertInfo where
  parseBlob = parseDirectoryCertInfo

instance Fetchable (Consensus, Digest SHA1State, Digest SHA256State) where
  parseBlob = parseConsensusDocument

data FetchItem = ConsensusDocument
               | KeyCertificate
               | Descriptors [ByteString]

instance Show FetchItem where
  show ConsensusDocument = "/tor/status-vote/current/consensus.z"
  show KeyCertificate    = "/tor/keys/authority.z"
  show (Descriptors _)   = error "Figure out how to get descriptors"

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
                  case decompress body of
                    Nothing    -> return (Left "Decompression failure.")
                    Just body' -> return (parseBlob body')

buildGet :: String -> ByteString
buildGet str = result
 where
  result      = pack (requestLine ++ userAgent ++ crlf)
  requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
  userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
  crlf        = "\r\n"

readResponse :: TorNetworkStack ls s -> s -> IO (Either String ByteString)
readResponse ns sock =
  do response <- recvAll ns sock
     case parse httpResponse response of
       Fail bstr _ err ->
         do let start = show (BS.take 10 bstr)
                msg = "Parser error: " ++ err ++ " [" ++ start ++ "]"
            return (Left msg)
       Done _ res ->
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
                Right `fmap` takeLazyByteString
 where
  crlf = char8 '\r' >> char8 '\n'
  keyval =
    do _ <- many1 (notWord8 13)
       _ <- crlf
       return ()

