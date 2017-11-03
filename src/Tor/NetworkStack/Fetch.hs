-- |Automatic fetching and decoding of resources needed for Tor; specifically,
-- this hides a lot of the HTTP GET cruft that would otherwise be sprinkled
-- about the code.
--
-- Users should avoid using this module for long-term projects. It ended up both
-- growing a little bit beyond what was intended, and also managed to be less
-- generally useful than I had thought. Thus, I suspect this module will be
-- overhauled in the not-too-distant future.
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
module Tor.NetworkStack.Fetch(
         FetchItem(..)
       , Fetchable
       , fetch
       , readResponse
       )
 where

-- FIXME: This whole interface could use a re-think.

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

-- |A set of types that are automatically fetchable by this subsystem.
class Fetchable a where
  -- |Parse a blob of incoming data, emitting either an error string of the
  -- item. A moral equivalent to ReadS, except for ByteStrings, and we're
  -- not planning to make this widely used.
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

-- |One of the things we can automatically fetch.
data FetchItem = ConsensusDocument
               | KeyCertificate
               | Descriptors
 deriving (Show)

-- |Given an item to fetch, get the directory and file name for that thing.
fetchItemFile :: FetchItem -> String
fetchItemFile ConsensusDocument = "/tor/status-vote/current/consensus.z"
fetchItemFile KeyCertificate    = "/tor/keys/authority.z"
fetchItemFile Descriptors       = "/tor/server/all.z"

-- |Given an item to fetch, get a time we should be willing to wait to download
-- and process that item.
fetchItemTime :: FetchItem -> Int
fetchItemTime ConsensusDocument =     60 * 1000000
fetchItemTime KeyCertificate    =     5  * 1000000
fetchItemTime Descriptors       = 3 * 60 * 1000000

-- |Fetch the given item from the given host and port, using the given network
-- stack, returning either the error that occurred fetching that item or the
-- item. The String used for the host will be directly passed to the network
-- stack's connect function without further processing, so you should think
-- about whether that means you need to address resolution or not.
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
                      Left err    ->
                        return (Left ("Decompression failure: " ++ show err))
                      Right body' ->
                        return (parseBlob (L.toStrict body'))
            `finally` close ns sock
 where
  timeout' tm io =
    do res <- timeout tm io
       case res of
         Nothing -> return (Left "Fetch timed out.")
         Just x  -> return x

-- |Build a GET request for the given resource.
buildGet :: String -> L.ByteString
buildGet str = result
 where
  result      = pack (requestLine ++ userAgent ++ crlf)
  requestLine = "GET " ++ str ++ " HTTP/1.0\r\n"
  userAgent   = "User-Agent: CERN-LineMode/2.15 libwww/2.17b3\r\n"
  crlf        = "\r\n"

-- |Read the response to a GET request. This returns the parsed interior of a
-- GET response, rather than the whole response, so one of the possible errors
-- you might receive is an HTTP response parsing error.
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
         Data.Attoparsec.ByteString.Done res () ->
           (Right . L.fromChunks . (res:)) `fmap` lazyRead
  --
  lazyRead :: IO [ByteString]
  lazyRead = unsafeInterleaveIO $ do chunk <- recv ns sock 4096
                                     if S.null chunk
                                        then return []
                                        else do rest <- lazyRead
                                                return (chunk : rest)

-- |An attoparsec parser for HTTP responses. This is not, in any way, fully
-- general.
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

