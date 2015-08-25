{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Tor.DataFormat.Consensus(
         Consensus(..)
       , Authority(..)
       , Router(..)
       , parseConsensusDocument
       )
 where

import Control.Applicative
import Crypto.Hash.Easy
import Data.Attoparsec.ByteString
import Data.ByteString(ByteString)
import Data.ByteString.Char8(unpack)
import qualified Data.ByteString as BS
import Data.Hourglass
import Data.Int
import Data.Map(Map)
import qualified Data.Map as Map
import Data.Version
import Data.Word
import Tor.DataFormat.Helpers

data Consensus = Consensus {
       conMethods             :: Maybe [Int]
     , conMethod              :: Int
     , conValidAfter          :: DateTime
     , conFreshUntil          :: DateTime
     , conValidUntil          :: DateTime
     , conVotingDelay         :: (Integer, Integer)
     , conSuggestedClientVers :: Maybe [Version]
     , conSuggestedServerVers :: Maybe [Version]
     , conKnownFlags          :: [String]
     , conParameters          :: [(String, Int32)]
     , conAuthorities         :: [Authority]
     , conRouters             :: [Router]
     , conBandwidthWeights    :: Map String Int32
     , conSignatures          :: [(Bool, ByteString, ByteString, ByteString)]
     }
 deriving (Show)

data Authority = Authority {
       authName       :: String
     , authIdent      :: ByteString
     , authAddress    :: String
     , authIP         :: String
     , authDirPort    :: Word16
     , authOnionPort  :: Word16
     , authContact    :: String
     , authVoteDigest :: ByteString
     }
 deriving (Show)

data Router = Router {
       rtrNickName       :: String
     , rtrIdentity       :: ByteString
     , rtrDigest         :: ByteString
     , rtrPubTime        :: DateTime
     , rtrIP             :: String
     , rtrOnionPort      :: Word16
     , rtrDirPort        :: Maybe Word16
     , rtrIP6Addrs       :: [(String, Word16)]
     , rtrStatus         :: [String]
     , rtrVersion        :: Maybe Version
     , rtrBandwidth      :: Maybe (Integer, [(String, String)])
     , rtrPortList       :: Maybe (Bool, [PortSpec])
     }
 deriving (Show)

parseConsensusDocument :: ByteString ->
                          Either String (Consensus, ByteString, ByteString)
parseConsensusDocument bstr =
  case parse consensusDocument bstr of
    Partial f -> processParse (f BS.empty)
    x         -> processParse x
 where
  (digest1, digest256) = generateHashes bstr
  processParse (Fail x _ err) = Left (err ++ " (around |" ++ show (BS.take 10 x) ++ "|)")
  processParse (Partial _ )   = Left "Incomplete consensus document!"
  processParse (Done _ res)   = Right (res, digest1, digest256)

generateHashes :: ByteString -> (ByteString, ByteString)
generateHashes infile = (sha1 message, sha256 message)
 where
  message  = run infile
  run bstr =
    case BS.span (/= 10) bstr of
      (start, finale) | "\ndirectory-signature " `BS.isPrefixOf` finale ->
        start `BS.append` "\ndirectory-signature "
      (start, rest) ->
        start `BS.append` (BS.singleton 10) `BS.append` run (BS.drop 1 rest)

consensusDocument :: Parser Consensus
consensusDocument =
  do _                      <- string "network-status-version 3\n"
     _                      <- string "vote-status consensus\n"
     conMethods             <- option Nothing $
                                 do _   <- string "consensus-methods" >> sp
                                    res <- sepBy1 consensusMethod sp
                                    _   <- nl
                                    return (Just res)
     conMethod              <- standardLine "consensus-method" consensusMethod
     conValidAfter          <- standardLine "valid-after" utcTime
     conFreshUntil          <- standardLine "fresh-until" utcTime
     conValidUntil          <- standardLine "valid-until" utcTime
     conVotingDelay         <- standardLine "voting-delay" $
                                 do vsec <- decimalNum (const True)
                                    _    <- sp
                                    dsec <- decimalNum (const True)
                                    return (vsec, dsec)
     conSuggestedClientVers <- option Nothing $
                                 standardLine "client-versions"
                                   (Just <$> sepBy1 torVersion (char8 ','))
     conSuggestedServerVers <- option Nothing $
                                 standardLine "server-versions"
                                   (Just <$> sepBy1 torVersion (char8 ','))
     conKnownFlags          <- standardLine "known-flags"
                                   (sepBy1 (unpack <$> flag) (char8 ' '))
     conParameters          <- standardLine "params" torParams --option [] $  
     conAuthorities         <- many1 authority
     conRouters             <- many1 router
     _                      <- string "directory-footer\n"
     conBandwidthWeights    <- option Map.empty $
                                 do _ <- string "bandwidth-weights "
                                    x <- bandwidthWeights
                                    _ <- nl
                                    return x
     conSignatures          <- many1 consensusSignature
     return Consensus{..}

consensusMethod :: Parser Int
consensusMethod = decimalNum (\ x -> (x >= 1) && (x <= 20))

torVersion :: Parser Version
torVersion =
  do versionBranch <- sepBy1 (decimalNum (const True)) (char8 '.')
     versionTags   <- option [] $ do _ <- char8 '-'
                                     tags <- sepBy1 (many1 alphaNum) (char8 '-')
                                     return (map toString tags)
     return Version{..}

flag :: Parser ByteString
flag = string "Authority"
   <|> string "BadExit"
   <|> string "BadDirectory"
   <|> string "Exit"
   <|> string "Fast"
   <|> string "Guard"
   <|> string "HSDir"
   <|> string "Named"
   <|> string "Stable"
   <|> string "Running"
   <|> string "Unnamed"
   <|> string "Valid"
   <|> string "V2Dir"

torParams :: Parser [(String, Int32)]
torParams = sepBy1 parameter (char8 ' ')
 where
  parameter =
    do x <- keyword
       _ <- char8 '='
       v <- decimalNum (const True)
       return (x, v)
  keyword = toString <$> many1 keywordChar
  keywordChar = satisfy (inClass "A-Za-z0-9_-")

authority :: Parser Authority
authority =
  do _              <- string "dir-source"
     _              <- sp
     authName       <- nickname
     _              <- sp
     authIdent      <- hexDigest
     _              <- sp
     authAddress    <- toString <$> many1 (notWord8 32)
     _              <- sp
     authIP         <- ip4
     _              <- sp
     authDirPort    <- decimalNum (const True)
     _              <- sp
     authOnionPort  <- decimalNum (const True)
     _              <- nl
     _              <- string "contact"
     _              <- sp
     authContact    <- toString <$> many1 (notWord8 10)
     _              <- nl
     _              <- string "vote-digest"
     _              <- sp
     authVoteDigest <- hexDigest
     _              <- nl
     return Authority{ .. }

router :: Parser Router
router =
  do _              <- string "r "
     rtrNickName    <- nickname
     _              <- sp
     rtrIdentity    <- decodeBase64' =<< many1 base64Char
     _              <- sp
     rtrDigest      <- decodeBase64' =<< many1 base64Char
     _              <- sp
     rtrPubTime     <- utcTime
     _              <- sp
     rtrIP          <- ip4
     _              <- sp
     rtrOnionPort   <- decimalNum (const True)
     _              <- sp
     rtrDirPort     <- maybe0 <$> decimalNum (const True)
     _              <- nl
     rtrIP6Addrs    <- many $ do _ <- string "a "
                                 a <- ip6
                                 _ <- char8 ':'
                                 p <- decimalNum (const True)
                                 _ <- nl
                                 return (a, p)
     _              <- string "s "
     rtrStatus      <- map unpack <$> sepBy1 flag (char8 ' ')
     _              <- nl
     rtrVersion     <- option Nothing $
                         do _ <- string "v Tor "
                            v <- torVersion
                            _ <- nl
                            return (Just v)
     rtrBandwidth   <- option Nothing $
                         do _ <- string "w Bandwidth="
                            b <- decimalNum (const True)
                            f <- many $ do _ <- sp
                                           x <- many1 alphaNum
                                           _ <- char8 '='
                                           v <- many1 alphaNum
                                           return (toString x, toString v)
                            _ <- nl
                            return (Just (b, f))
     rtrPortList    <- option Nothing $
                         do _ <- string "p "
                            a <-  (string "accept" >> return True)
                              <|> (string "reject" >> return False)
                            _ <- sp
                            p <- sepBy1 portSpec (char8 ',')
                            _ <- nl
                            return (Just (a, p))
     return Router{..}
 where
  maybe0 0 = Nothing
  maybe0 x = Just x

bandwidthWeights :: Parser (Map String Int32)
bandwidthWeights = Map.fromList <$> sepBy1 bweight (char8 ' ')
 where
  bweight =
    do weight <- toString <$> many1 alphaNum
       _      <- char8 '='
       value  <- decimalNum (const True)
       return (weight, value)

consensusSignature :: Parser (Bool, ByteString, ByteString, ByteString)
consensusSignature =
  do _     <- string "directory-signature"
     sha1p <- option True $ (string "sha1"   >> return True)
                        <|> (string "sha256" >> return False)
     _     <- sp
     ident <- hexDigest
     _     <- sp
     skdig <- hexDigest
     _     <- nl
     _     <- string "-----BEGIN SIGNATURE-----\n"
     let end = string "-----END SIGNATURE-----\n"
     sig   <- decodeBase64 =<< manyTill base64Char end
     return (sha1p, ident, skdig, sig)

-- -----------------------------------------------------------------------------

decodeBase64' :: [Word8] -> Parser ByteString
decodeBase64' bytes =
  case length bytes `mod` 4 of
    0 -> decodeBase64 bytes
    1 -> error "Does this happen?"
    2 -> decodeBase64 (bytes ++ [61,61])
    3 -> decodeBase64 (bytes ++ [61])
    _ -> error "The universe appears to be broken."
