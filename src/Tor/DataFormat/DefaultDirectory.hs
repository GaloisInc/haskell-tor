{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
-- |Routines for parsing and rendering the default directories included in this
-- binary.
module Tor.DataFormat.DefaultDirectory(
         DefaultDirectory(..)
       , parseDefaultDirectory
       )
 where

import Data.Attoparsec.ByteString
import Data.ByteString(ByteString)
import Data.Word
import Tor.DataFormat.Helpers

-- |A default directory for pulling consensus and other data.
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

-- FIXME: Make this handle partial input
-- |Parse a directory structure.
parseDefaultDirectory :: ByteString -> Either String DefaultDirectory
parseDefaultDirectory bstr =
  case parse defaultDirectory bstr of
    Fail _ _ err -> Left err
    Partial _    -> Left "Incomplete default directory!"
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

