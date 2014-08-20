{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.DataFormat.DefaultDirectory(
         DefaultDirectory(..)
       , parseDefaultDirectory
       )
 where

import Data.Attoparsec.ByteString.Lazy
import Data.ByteString.Lazy(ByteString)
import Data.Word
import Tor.DataFormat.Helpers

data DefaultDirectory = DefaultDirectory {
       ddirNickname    :: String
     , ddirIsBridge    :: Bool
     , ddirAddress     :: String
     , ddirOnionPort   :: Word16
     , ddirDirPort     :: Word16
     , ddirV3Ident     :: Maybe ByteString
     , ddirFingerprint :: ByteString
     }
 deriving (Show)

parseDefaultDirectory :: ByteString -> Either String DefaultDirectory
parseDefaultDirectory bstr =
  case parse defaultDirectory bstr of
    Fail _ _ err -> Left err
    Done _   res -> Right res

defaultDirectory :: Parser DefaultDirectory
defaultDirectory =
  do ddirNickname               <- nickname
     _                          <- sp
     _                          <- string "orport="
     ddirOnionPort              <- port False
     _                          <- sp
     ddirV3Ident                <- option Nothing $ do res <- v3Ident
                                                       _   <- sp
                                                       return (Just res)
     ddirIsBridge               <- option False $ do _ <- string "bridge "
                                                     return True
     (ddirAddress, ddirDirPort) <- addrPort
     ddirFingerprint            <- fingerprint
     return DefaultDirectory{..}

v3Ident :: Parser ByteString
v3Ident =
  do _ <- string "v3ident="
     hexDigest

addrPort :: Parser (String, Word16)
addrPort =
  do a <- ip4
     _ <- char8 ':'
     p <- port False
     return (a, p)

fingerprint :: Parser ByteString
fingerprint =
  do parts <- count 10 (sp >> toString `fmap` count 4 hexDigit)
     return (readHex (concat parts))

