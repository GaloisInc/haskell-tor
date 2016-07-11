{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
-- |Routines for parsing router descriptions from a directory listing.
module Tor.DataFormat.RouterDesc(
         parseDirectory
       )
 where

import Control.Applicative
import Crypto.Error
import Crypto.Hash.Easy
import qualified Crypto.PubKey.Curve25519 as Curve
import Crypto.PubKey.RSA.PKCS15
import Data.Attoparsec.ByteString
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Hourglass
import Data.Map(Map)
import qualified Data.Map.Strict as Map
import Data.String
import Tor.DataFormat.Helpers
import Tor.RouterDesc

-- FIXME: Accept partial input.
-- |Parse a directory listing full of router descriptions, returning, for each
-- entry, either a parse error or the parsed router description.
parseDirectory :: ByteString -> [Either String RouterDesc]
parseDirectory bstr = map parseChunk (chunkRouters bstr)
 where
  parseChunk (chunk, signedPortion) =
    case parse parseRouterDesc chunk of
      Partial f -> processParse signedPortion (f BS.empty)
      x         -> processParse signedPortion x
  processParse _ (Fail _ _ _) = Left "Router description failed to parse."
  processParse _ (Partial _)  = Left "Partial data for router description."
  processParse signedPortion (Done leftover res) | BS.null leftover =
    let key  = routerSigningKey res
        sig  = routerSignature res
        body = sha1 signedPortion
        -- Tor uses a weird variation on PKCS signing in which they don't
        -- transmit the hash type
    in if verify noHash key body sig
          then Right res
          else Left "RSA verification failed."
  processParse _ _ =   Left "Unconsumed input in router description."

chunkRouters :: ByteString -> [(ByteString, ByteString)]
chunkRouters bstr =
  case nextRouter bstr of
    Nothing ->
      []
    Just (routerHeader, routerAll, rest) ->
      (routerAll, routerHeader) : chunkRouters rest

nextRouter :: ByteString -> Maybe (ByteString, ByteString, ByteString)
nextRouter orig = goState1 orig 0
 where
  goState1 bstr off =
   case BSC.uncons bstr of
     Nothing -> Nothing
     Just ('r', rest) ->
       let (start, possibleSig) = BSC.splitAt 17 bstr
       in if BSC.unpack start == "router-signature\n"
             then let mainDesc = BSC.take (off + 17) orig
                  in goState2 mainDesc (off + 17) possibleSig 0
             else goState1 rest (off + 1)
     Just (_, rest) ->
       goState1 rest (off + 1)
  --
  goState2 :: ByteString -> Int -> ByteString -> Int ->
              Maybe (ByteString, ByteString, ByteString)
  goState2 mainDesc mainoff bstr off =
    case BSC.uncons bstr of
      Nothing ->
        Just (mainDesc, orig, BS.empty)
      Just ('r', rest) ->
        let start = BS.take 7 bstr
        in if BSC.unpack start == "router "
              then let (ent, rest') = BSC.splitAt mainoff orig
                   in Just (mainDesc, ent, rest')
              else goState2 mainDesc (mainoff + 1) rest (off + 1)
      Just (_, rest) ->
       goState2 mainDesc (mainoff + 1) rest (off + 1) 

-- ----------------------------------------------------------------------------

parseRouterDesc :: Parser RouterDesc
parseRouterDesc =
  do initial <- routerStart
     result  <- runOptionals initial initialParseState
     _       <- many newline
     return result
 where
  runOptionals router state =
    do let options = map (\ parserGen -> parserGen state router)
                         wrappedOptionParsers
       (router', state', final) <- choice options
       let router'' = checkFinalStates router' state'
       if final
         then return router''
         else runOptionals router' state'
 
data ParseAmount = Never | AtMostOnce | ExactlyOnce | AnyNumber | EndsRouter
 deriving (Eq, Show)

initialParseState :: Map Int ParseAmount
initialParseState = Map.fromList (map (\ (a,b,_,_) -> (a,b)) routerDescOptions)

type OptionParser = Map Int ParseAmount -> RouterDesc ->
                    Parser (RouterDesc, Map Int ParseAmount, Bool)

wrappedOptionParsers :: [OptionParser]
wrappedOptionParsers = map addWrapper routerDescOptions

addWrapper :: (Int, ParseAmount, String, RouterDesc -> Parser RouterDesc) ->
              OptionParser
addWrapper (idx, _, oname, parser) state r =
  do res <- parser r <?> oname
     case Map.lookup idx state of
       Nothing ->
         let res' = warn res ("Failed to look up option " ++ show idx)
         in return (res', state, True)
       -- Good cases
       Just ExactlyOnce ->
         let state' = Map.insert idx Never state
         in return (res, state', False)
       Just AtMostOnce ->
         let state' = Map.insert idx Never state
         in return (res, state', False)
       Just AnyNumber ->
         return (res, state, False)
       Just EndsRouter ->
         return (res, state, True)
       -- Bad cases
       Just Never ->
         let res' = warn res ("Got multiple versions of option " ++ oname)
         in return (res', state, False)

checkFinalStates :: RouterDesc -> Map Int ParseAmount -> RouterDesc
checkFinalStates inr stateMap = checkMissing inr (Map.toList stateMap)
 where
  checkMissing r [] = r
  checkMissing r ((idx, ExactlyOnce) : rest) =
    let r' = warn r ("Missing field: " ++ getName idx routerDescOptions)
    in checkMissing r' rest
  checkMissing r (_ : rest) =
    checkMissing r rest
  --
  getName _ [] = "unkwnown field"
  getName x ((y,_,n,_):rest)
    | x == y    = n
    | otherwise = getName x rest

-- ----------------------------------------------------------------------------

warn :: RouterDesc -> String -> RouterDesc
warn r msg = r{ routerParseLog = routerParseLog r ++ [msg] }

-- ----------------------------------------------------------------------------

routerDescOptions :: [(Int, ParseAmount, String, RouterDesc -> Parser RouterDesc)]
routerDescOptions = [
    ( 0, ExactlyOnce, "bandwidth",          bandwidth)
  , ( 1, AtMostOnce,  "platform",           platform)
  , ( 2, ExactlyOnce, "published",          published)
  , ( 3, AtMostOnce,  "fingerprint",        fingerprint)
  , ( 4, AtMostOnce,  "hibernating",        hibernating)
  , ( 5, AtMostOnce,  "uptime",             uptime)
  , ( 6, ExactlyOnce, "onionKey",           onionKey)
  , ( 7, AtMostOnce,  "ntorOnionKey",       ntorOnionKey)
  , ( 8, ExactlyOnce, "SigningKey",         signingKey)
  , ( 9, AnyNumber,   "ExitRule",           exitRule)
  , (10, AtMostOnce,  "ipv6Policy",         ipv6Policy)
  , (11, EndsRouter,  "routerSignature",    routerSig)
  , (12, AtMostOnce,  "contact",            contactInfo)
  , (13, AtMostOnce,  "family",             family)
  , (14, AtMostOnce,  "readHistory",        readHistory)
  , (15, AtMostOnce,  "writeHistory",       writeHistory)
  , (16, AtMostOnce,  "eventDNS",           eventDNS)
  , (17, AtMostOnce,  "cachesExtraInfo",    cachesExtraInfo)
  , (18, AtMostOnce,  "extraInfoDigest",    extraInfoDigest)
  , (19, AtMostOnce,  "hiddenServiceDir",   hiddenServiceDir)
  , (20, AtMostOnce,  "protocols",          protocols)
  , (21, AtMostOnce,  "allowSingleHopExits",allowSingleHopExits)
  , (22, AnyNumber,   "orAddress",          orAddress)
  ]


routerStart :: Parser RouterDesc
routerStart =
  do _         <- string "router"
     _         <- whitespace
     nick      <- nickname
     _         <- whitespace
     addr      <- ip4
     _         <- whitespace
     orport    <- port False
     _         <- whitespace
     socksport <- port True
     _         <- whitespace
     dirport   <- port True
     let dirport' = if dirport == 0 then Nothing else Just dirport
     _         <- newline
     let result = RouterDesc {
           routerNickname                = nick
         , routerIPv4Address             = addr
         , routerORPort                  = orport
         , routerDirPort                 = dirport'
         , routerAvgBandwidth            = 0
         , routerBurstBandwidth          = 0
         , routerObservedBandwidth       = 0
         , routerPlatformName            = ""
         , routerEntryPublished          = timeFromElapsed (Elapsed 0)
         , routerFingerprint             = BS.empty
         , routerHibernating             = False
         , routerUptime                  = Nothing
         , routerOnionKey                = error "No onion key!"
         , routerNTorOnionKey            = Nothing
         , routerSigningKey              = error "No signing key!"
         , routerExitRules               = []
         , routerIPv6Policy              = Left [PortSpecRange 1 65535]
         , routerSignature               = BS.empty
         , routerContact                 = Nothing
         , routerFamily                  = []
         , routerReadHistory             = Nothing
         , routerWriteHistory            = Nothing
         , routerCachesExtraInfo         = False
         , routerExtraInfoDigest         = Nothing
         , routerHiddenServiceDir        = Nothing
         , routerLinkProtocolVersions    = []
         , routerCircuitProtocolVersions = []
         , routerAllowSingleHopExits     = False
         , routerAlternateORAddresses    = []
         , routerParseLog                = []
         , routerStatus                  = []
         }
     if socksport /= 0
        then return (warn result "RouterDesc incorrectly set nonzero SOCKS port.")
        else return result

bandwidth :: RouterDesc -> Parser RouterDesc
bandwidth r =
  do _     <- string "bandwidth"
     _     <- whitespace
     avg   <- decimalNum (const True)
     _     <- whitespace
     burst <- decimalNum (const True)
     _     <- whitespace
     obs   <- decimalNum (const True)
     _     <- newline
     return r{ routerAvgBandwidth      = avg
             , routerBurstBandwidth    = burst
             , routerObservedBandwidth = obs }

platform :: RouterDesc -> Parser RouterDesc
platform r =
  do _     <- string "platform"
     _     <- whitespace
     ident <- toString <$> manyTill anyWord8 newline
     return r{ routerPlatformName = ident }

published :: RouterDesc -> Parser RouterDesc
published r =
  do _ <- string "published"
     _ <- whitespace
     t <- utcTime
     _ <- newline
     return r{ routerEntryPublished = t }

fingerprint :: RouterDesc -> Parser RouterDesc
fingerprint r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "fingerprint"
     _ <- whitespace
     fp <- sepBy1 (count 4 hexDigit) whitespace1
     _ <- newline
     return r{ routerFingerprint = readHex (toString (concat fp)) }

hibernating :: RouterDesc -> Parser RouterDesc
hibernating r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "hibernating"
     _ <- whitespace
     b <- bool
     _ <- newline
     return r{ routerHibernating = b }

uptime :: RouterDesc -> Parser RouterDesc
uptime r =
  do _ <- string "uptime"
     _ <- whitespace
     n <- decimalNum (const True)
     _ <- newline
     return r{ routerUptime = Just n }

onionKey :: RouterDesc -> Parser RouterDesc
onionKey r =
  do _ <- string "onion-key"
     _ <- newline
     k <- publicKey
     return r{ routerOnionKey = k }

ntorOnionKey :: RouterDesc -> Parser RouterDesc
ntorOnionKey r =
  do _ <- string "ntor-onion-key"
     _ <- whitespace
     x <- decodeBase64 =<< manyTill base64Char newline
     case Curve.publicKey x of
       CryptoPassed k -> return r{ routerNTorOnionKey = Just k}
       CryptoFailed e ->
         fail ("Failure decoding curve25519 public key: " ++ show e)

signingKey :: RouterDesc -> Parser RouterDesc
signingKey r =
  do _ <- string "signing-key"
     _ <- newline
     k <- publicKey
     return r{ routerSigningKey = k }

exitRule :: RouterDesc -> Parser RouterDesc
exitRule r =
  do builder <- accept <|> reject
     _       <- whitespace
     (a, p)  <- exitPattern
     _       <- newline
     return r{ routerExitRules = routerExitRules r ++ [builder a p] }
 where
  accept = string "accept" >> return ExitRuleAccept
  reject = string "reject" >> return ExitRuleReject

ipv6Policy :: RouterDesc -> Parser RouterDesc
ipv6Policy r =
  do _ <- string "ipv6-policy"
     _ <- whitespace
     b <- accept <|> reject
     _ <- whitespace
     l <- sepBy1 portSpec (char8 ',')
     _ <- newline
     return r{ routerIPv6Policy = b l }
 where
  accept = string "accept" >> return Right
  reject = string "reject" >> return Left

routerSig :: RouterDesc -> Parser RouterDesc
routerSig r =
  do _ <- string "router-signature"
     _ <- newline
     _ <- string "-----BEGIN SIGNATURE-----\n"
     let end = string "-----END SIGNATURE-----"
     sig <- decodeBase64 =<< manyTill base64Char end
     _ <- newline
     return r{ routerSignature = sig }

contactInfo :: RouterDesc -> Parser RouterDesc
contactInfo r =
  do _ <- string "contact"
     _ <- whitespace
     l <- manyTill anyWord8 newline
     return r{ routerContact = Just (toString l) }

family :: RouterDesc -> Parser RouterDesc
family r =
  do _ <- string "family"
     _ <- whitespace
     l <- sepBy1 familyDef whitespace
     _ <- newline
     return r{ routerFamily = l }
 where
  familyDef = digestWithName <|> digestWithoutName <|> nameWithoutDigest
  digestWithName =
    do _ <- char8 '$'
       d <- hexDigest
       _ <- char8 '='
       n <- nickname
       return (NodeFamilyBoth n d)
  digestWithoutName =
    do _ <- char8 '$'
       d <- hexDigest
       return (NodeFamilyDigest d)
  nameWithoutDigest =
    do n <- nickname
       return (NodeFamilyNickname n)

readHistory :: RouterDesc -> Parser RouterDesc
readHistory r =
  do rhist <- history "read-history"
     return r{ routerReadHistory = Just rhist }

writeHistory :: RouterDesc -> Parser RouterDesc
writeHistory r =
  do whist <- history "write-history"
     return r{ routerWriteHistory = Just whist }

history :: String -> Parser (DateTime, Int, [Int])
history kind =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string (fromString kind)
     _ <- whitespace
     t <- utcTime
     _ <- whitespace
     n <- decimalNum (const True)
     _ <- whitespace
     v <- sepBy1 (decimalNum (const True)) (char8 ',')
     _ <- newline
     return (t, n, v)

eventDNS :: RouterDesc -> Parser RouterDesc
eventDNS r =
  do _ <- string "eventdns"
     _ <- whitespace
     _ <- bool
     _ <- newline
     return (warn r "Router used obsolete 'eventdns' flag.")

cachesExtraInfo :: RouterDesc -> Parser RouterDesc
cachesExtraInfo r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "caches-extra-info"
     _ <- newline
     return r{ routerCachesExtraInfo = True }

extraInfoDigest :: RouterDesc -> Parser RouterDesc
extraInfoDigest r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "extra-info-digest"
     _ <- whitespace
     d <- toString <$> manyTill hexDigit newline
     return r{ routerExtraInfoDigest = Just (readHex d) }

hiddenServiceDir :: RouterDesc -> Parser RouterDesc
hiddenServiceDir r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "hidden-service-dir"
     _ <- whitespace
     v <- option 2 $ decimalNum (const True)
     _ <- newline
     return r{ routerHiddenServiceDir = Just v }

protocols :: RouterDesc -> Parser RouterDesc
protocols r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "protocols"
     _ <- whitespace
     _ <- string "Link"
     _ <- whitespace
     l <- sepBy (decimalNum (const True)) whitespace1
     _ <- whitespace
     _ <- string "Circuit"
     _ <- whitespace
     c <- sepBy (decimalNum (const True)) whitespace1
     _ <- newline
     return r{ routerLinkProtocolVersions    = l
             , routerCircuitProtocolVersions = c }

allowSingleHopExits :: RouterDesc -> Parser RouterDesc
allowSingleHopExits r =
  do _ <- option "" (string "opt")
     _ <- whitespace
     _ <- string "allow-single-hop-exits"
     _ <- newline
     return r{ routerAllowSingleHopExits = True }

orAddress :: RouterDesc -> Parser RouterDesc
orAddress r =
  do _    <- option "" (string "opt")
     _    <- whitespace
     _    <- string "or-address"
     _    <- whitespace
     addr <- ip4 <|> ip6
     _    <- char8 ':'
     pnum <- port False
     _    <- newline
     let prev = routerAlternateORAddresses r
     return r{ routerAlternateORAddresses = prev ++ [(addr, pnum)] }

-- ----------------------------------------------------------------------------

exitPattern :: Parser (AddrSpec, PortSpec)
exitPattern =
  do a <- addrSpec
     _ <- char8 ':'
     p <- portSpec
     return (a, p)
  <?> "exitPattern"
