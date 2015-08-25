module Tor.RouterDesc.Render(
         renderRouterDesc
       )
 where

import Control.Monad
import Crypto.Hash.Easy
import Crypto.Number.Serialize
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Data.Bits
import Data.ByteString.Base64
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Char hiding (isHexDigit, isAlphaNum)
import Data.Hourglass
import MonadLib
import MonadLib.Monads
import Tor.RouterDesc

type Render = Writer String

putWord :: String -> Render ()
putWord x = put x >> put " "

putWord' :: Show a => a -> Render ()
putWord' x = put (show x) >> put " "

endLine :: Render ()
endLine = put "\n"

putFourGroups :: String -> Render ()
putFourGroups [] = return ()
putFourGroups xs =
  do let (f, rest) = splitAt 4 xs
     putWord f
     putFourGroups rest

putPublicKey :: PublicKey -> Render ()
putPublicKey (PublicKey _ n _) =
  do let encoded = encode (i2ospOf_ (1024 `div` 8) n)
     put "-----BEGIN RSA PUBLIC KEY-----\n"
     putLines (BSC.unpack encoded)
     put "-----END RSA PUBLIC KEY-----\n"

putLines :: String -> Render ()
putLines [] = return ()
putLines xs =
  do let (f, rest) = splitAt 64 xs
     put f
     endLine
     putLines rest

putSeperated :: String -> (a -> Render ()) -> [a] -> Render ()
putSeperated _   _      []       = return ()
putSeperated _   render [x]      = render x
putSeperated sep render (x:rest) =
  do render x
     put sep
     putSeperated sep render rest

-- ----------------------------------------------------------------------------

renderRouterDesc :: RouterDesc -> PrivateKey -> String
renderRouterDesc r k = snd (runWriter (renderRouterDesc' r k))

renderRouterDesc' :: RouterDesc -> PrivateKey -> Render ()
renderRouterDesc' r k =
  do let (_, desc) = runWriter $ do renderRouterLine r
                                    renderBandwidth r
                                    renderPlatform r
                                    renderPublished r
                                    renderFingerprint r
                                    renderHibernating r
                                    renderUptime r
                                    renderOnionKey r
                                    renderNTorKey r
                                    renderSigningKey r
                                    renderExitRules r
                                    renderIPv6Policy r
                                    renderContactInfo r
                                    renderFamily r
                                    renderReadHistory r
                                    renderWriteHistory r
                                    renderCachesExtraInfo r
                                    renderExtraInfoDigest r
                                    renderHiddenServiceDir r
                                    renderProtocols r
                                    renderAllowSingleHopExits r
                                    renderAltAddresses r
                                    putWord "router-signature"
                                    endLine
     let descbstr = BSC.pack desc
         msignature = sign Nothing noHash k (sha1 descbstr)
     case msignature of
       Left _          -> return () -- error?
       Right signature ->
         do let encodedsig = encode signature
            put desc
            put "-----BEGIN SIGNATURE-----\n"
            putLines (BSC.unpack encodedsig)
            put "-----END SIGNATURE-----\n"

renderRouterLine :: RouterDesc -> Render ()
renderRouterLine r =
  do putWord "router"
     putWord (routerNickname r)
     putWord (routerIPv4Address r)
     putWord' (routerORPort r)
     putWord "0"
     case routerDirPort r of
       Nothing -> putWord "0"
       Just x  -> putWord' x
     endLine

renderBandwidth :: RouterDesc -> Render ()
renderBandwidth r =
  do putWord "bandwidth"
     putWord' (routerAvgBandwidth r)
     putWord' (routerBurstBandwidth r)
     putWord' (routerObservedBandwidth r)
     endLine

renderPlatform :: RouterDesc -> Render ()
renderPlatform r =
  when (routerPlatformName r /= "") $
    do putWord "platform"
       put (routerPlatformName r)
       endLine

renderPublished :: RouterDesc -> Render ()
renderPublished r =
  do putWord "published"
     let fmt = [Format_Year4, Format_Text '-', Format_Month2, Format_Text '-',
                Format_Day2, Format_Text ' ', Format_Hour, Format_Text ':',
                Format_Minute, Format_Text ':', Format_Second]
     put (timePrint fmt (routerEntryPublished r))
     endLine

renderFingerprint :: RouterDesc -> Render ()
renderFingerprint r =
  unless (BS.null (routerFingerprint r)) $
    do putWord "opt"
       putWord "fingerprint"
       let fprint = showHex (routerFingerprint r)
       putFourGroups fprint
       endLine

renderHibernating :: RouterDesc -> Render ()
renderHibernating r =
  when (routerHibernating r) $
    do putWord "opt"
       putWord "hibernating"
       putWord "1"
       endLine

renderUptime :: RouterDesc -> Render ()
renderUptime r =
  case routerUptime r of
    Nothing -> return ()
    Just x ->
      do putWord "uptime"
         putWord' x
         endLine

renderOnionKey :: RouterDesc -> Render ()
renderOnionKey r =
  do putWord "onion-key"
     endLine
     putPublicKey (routerOnionKey r)

renderNTorKey :: RouterDesc -> Render ()
renderNTorKey r =
  case routerNTorOnionKey r of
    Nothing -> return ()
    Just k -> 
      do putWord "ntor-onion-key"
         putWord (BSC.unpack (encode k))
         endLine

renderSigningKey :: RouterDesc -> Render ()
renderSigningKey r =
  do putWord "signing-key"
     endLine
     putPublicKey (routerSigningKey r)

renderExitRules :: RouterDesc -> Render ()
renderExitRules r = mapM_ renderExitRule (routerExitRules r)
 where
  renderExitRule (ExitRuleAccept a p ) = putWord "accept" >> renderRest a p
  renderExitRule (ExitRuleReject a p ) = putWord "reject" >> renderRest a p
  renderRest a p =
    do renderAddrSpec a
       put ":"
       renderPortSpec p
       endLine

renderAddrSpec :: AddrSpec -> Render ()
renderAddrSpec AddrSpecAll = put "*"
renderAddrSpec (AddrSpecIP4 a) = put a
renderAddrSpec (AddrSpecIP6 a) = put "[" >> put a >> put "]"
renderAddrSpec (AddrSpecIP4Mask a m) = put a >> put "/" >> put m
renderAddrSpec (AddrSpecIP4Bits a b) = put a >> put "/" >> put (show b)
renderAddrSpec (AddrSpecIP6Bits a b) = put a >> put "/" >> put (show b)

renderPortSpec :: PortSpec -> Render ()
renderPortSpec PortSpecAll = put "*"
renderPortSpec (PortSpecSingle p) = put (show p)
renderPortSpec (PortSpecRange p q) = put (show p) >> put "-" >> put (show q)

renderIPv6Policy :: RouterDesc -> Render ()
renderIPv6Policy r =
  case routerIPv6Policy r of
    Left [PortSpecRange 1 65535] ->
      return ()
    Left ps ->
      do putWord "ipv6-policy reject"
         putSeperated "," renderPortSpec ps
         endLine
    Right ps ->
      do putWord "ipv6-policy accept"
         putSeperated "," renderPortSpec ps
         endLine

renderContactInfo :: RouterDesc -> Render ()
renderContactInfo r =
  case routerContact r of
    Nothing -> return ()
    Just x ->
      do putWord "contact"
         put x
         endLine

renderFamily :: RouterDesc -> Render ()
renderFamily r =
  unless (null (routerFamily r)) $
    do putWord "family"
       putSeperated " " renderRouterFamily (routerFamily r)
 where
  renderRouterFamily :: (Maybe ByteString, Maybe [Char]) -> Render ()
  renderRouterFamily (Nothing, Nothing) = return () -- fail?
  renderRouterFamily (Just x,  Nothing) =
    do put "$"
       put (showHex x)
  renderRouterFamily (Nothing, Just y) =
    do put y
  renderRouterFamily (Just x,  Just y) =
    do put "$"
       put (showHex x)
       put "="
       put y

renderReadHistory :: RouterDesc -> Render ()
renderReadHistory r = renderHistory "read" (routerReadHistory r)

renderWriteHistory :: RouterDesc -> Render ()
renderWriteHistory r = renderHistory "write" (routerWriteHistory r)

renderHistory :: String -> Maybe (DateTime, Int, [Int]) -> Render ()
renderHistory _         Nothing                          =
  return ()
renderHistory histtype (Just (tstamp, interval, counts)) =
  do put histtype
     putWord "-history"
     let fmt = [Format_Year4, Format_Text '-', Format_Month2, Format_Text '-',
                Format_Day2, Format_Text ' ', Format_Hour, Format_Text ':',
                Format_Minute, Format_Text ':', Format_Second]
     put (timePrint fmt tstamp)
     putWord' interval
     putSeperated "," (put . show) counts
     endLine

renderCachesExtraInfo :: RouterDesc -> Render ()
renderCachesExtraInfo r =
  when (routerCachesExtraInfo r) $
    do putWord "caches-extra-info"
       endLine

renderExtraInfoDigest :: RouterDesc -> Render ()
renderExtraInfoDigest r =
  case routerExtraInfoDigest r of
    Nothing ->
      return ()
    Just x  ->
      do putWord "extra-info-digest"
         putWord (showHex x)
         endLine

renderHiddenServiceDir :: RouterDesc -> Render ()
renderHiddenServiceDir r =
  case routerHiddenServiceDir r of
    Nothing ->
      return ()
    Just x  ->
      do putWord "hidden-service-dir"
         putWord' x
         endLine

renderProtocols :: RouterDesc -> Render ()
renderProtocols r =
  case (routerLinkProtocolVersions r, routerCircuitProtocolVersions r) of
    ([], [])   -> return ()
    (lvs, cvs) ->
      do putWord "protocols"
         putWord "Link"
         mapM_ putWord' lvs
         putWord "Circuit"
         mapM_ putWord' cvs
         endLine

renderAllowSingleHopExits :: RouterDesc -> Render ()
renderAllowSingleHopExits r =
  when (routerAllowSingleHopExits r) $
    do putWord "allow-single-hop-exits"
       endLine

renderAltAddresses :: RouterDesc -> Render ()
renderAltAddresses r =
  unless (null (routerAlternateORAddresses r)) $
    forM_ (routerAlternateORAddresses r) $
      \ (addr, orport) ->
        do putWord "or-address"
           put     $ if any (== ':') addr
                       then "[" ++ addr ++ "]"
                       else addr
           put ":"
           putWord' orport
           endLine

showHex :: ByteString -> String
showHex = BS.foldr addChars ""
 where
  addChars x acc = hexChar (x `shiftR` 4) : hexChar (x .&. 0xF) : acc
  hexChar = toUpper . intToDigit . fromIntegral


