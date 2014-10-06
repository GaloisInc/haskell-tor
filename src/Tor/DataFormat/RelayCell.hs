module Tor.DataFormat.RelayCell(
         RelayCell(..),      putRelayCell,      getRelayCell
       ,                     parseRelayCell,    renderRelayCell
       , ExtendSpec(..),     putExtendSpec,     getExtendSpec
       , RelayEndReason(..), putRelayEndReason, getRelayEndReason
       , putRelayCellGuts
       , RelayIntro1Data(..)
       )
 where

import Control.Applicative
import Control.Monad
import Data.Attoparsec.ByteString.Lazy
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.ByteString.Lazy.Char8(pack,unpack)
import Data.Digest.Pure.SHA1
import Data.Word
import Tor.DataFormat.Helpers(toString, ip4, ip6, char8, decimalNum)
import Tor.DataFormat.TorAddress
import Tor.DataFormat.TorCell

data RelayCell =
    RelayBegin                 { relayStreamId       :: Word16
                               , relayBeginAddress   :: TorAddress
                               , relayBeginPort      :: Word16
                               , relayBeginIPv4OK    :: Bool
                               , relayBeginIPv6OK    :: Bool
                               , relayBeginIPv6Pref  :: Bool }
  | RelayData                  { relayStreamId       :: Word16
                               , relayData           :: ByteString }
  | RelayEnd                   { relayStreamId       :: Word16
                               , relayEndReason      :: RelayEndReason }
  | RelayConnected             { relayStreamId       :: Word16
                               , relayConnectedAddr  :: TorAddress
                               , relayConnectedTTL   :: Word32 }
  | RelaySendMe                { relayStreamId       :: Word16 }
  | RelayExtend                { relayStreamId       :: Word16
                               , relayExtendAddress  :: TorAddress
                               , relayExtendPort     :: Word16
                               , relayExtendSkin     :: ByteString
                               , relayExtendIdent    :: ByteString }
  | RelayExtended              { relayStreamId       :: Word16
                               , relayExtendedData   :: ByteString }
  | RelayTruncate              { relayStreamId       :: Word16 }
  | RelayTruncated             { relayStreamId       :: Word16 
                               , relayTruncatedRsn   :: DestroyReason }
  | RelayDrop                  { relayStreamId       :: Word16 }
  | RelayResolve               { relayStreamId       :: Word16
                               , relayResolveName    :: String }
  | RelayResolved              { relayStreamId       :: Word16
                               , relayResolvedAddrs  :: [(TorAddress,Word32)]}
  | RelayBeginDir              { relayStreamId       :: Word16 }
  | RelayExtend2               { relayStreamId       :: Word16
                               , relayExtendTarget   :: [ExtendSpec]
                               , relayExtendType     :: Word16
                               , relayExtendData     :: ByteString }
  | RelayExtended2             { relayStreamId       :: Word16
                               , relayExtendedData   :: ByteString }
  | RelayEstablishIntro        { relayStreamId       :: Word16
                               , relayEstIntKey      :: ByteString
                               , relayEstIntSessHash :: ByteString
                               , relayEstIntSig      :: ByteString }
  | RelayEstablishRendezvous   { relayStreamId       :: Word16
                               , relayEstRendCookie  :: ByteString }
  | RelayIntroduce1            { relayStreamId       :: Word16
                               , relayIntro1KeyId    :: ByteString
                               , relayIntro1Data     :: ByteString }
  | RelayIntroduce2            { relayStreamId       :: Word16
                               , relayIntro2Data     :: ByteString }
  | RelayRendezvous1           { relayStreamId       :: Word16
                               , relayRendCookie     :: ByteString
                               , relayRendGY         :: ByteString
                               , relayRendKH         :: ByteString}
  | RelayRendezvous2           { relayStreamId       :: Word16
                               , relayRendGY         :: ByteString
                               , relayRendKH         :: ByteString }
  | RelayIntroEstablished      { relayStreamId       :: Word16 }
  | RelayRendezvousEstablished { relayStreamId       :: Word16 }
  | RelayIntroduceAck          { relayStreamId       :: Word16 }
 deriving (Eq, Show)

data RelayIntro1Data =
    RelayIntro1v0 { intRendPoint     :: ByteString
                  , intRendCookie    :: ByteString
                  , intRendgx1       :: ByteString }
  | RelayIntro1v1 { intRendPoint     :: ByteString
                  , intRendCookie    :: ByteString
                  , intRendgx1       :: ByteString }
  | RelayIntro1v2 { intRendPointIP   :: String
                  , intRendPointPort :: Word16
                  , intRendPointId   :: ByteString
                  , intRendOnionKey  :: ByteString
                  , intRendCookie    :: ByteString
                  , intRendgx1       :: ByteString }
  | RelayIntro1v3 { intAuthType      :: Word8
                  , intAuthData      :: ByteString
                  , intRendPointIP   :: String
                  , intRendPointPort :: Word16
                  , intRendPointId   :: ByteString
                  , intRendOnionKey  :: ByteString
                  , intRendCookie    :: ByteString
                  , intRendgx1       :: ByteString }


getRelayCell :: Get (ByteString, RelayCell)
getRelayCell =
  do cmd    <- getWord8
     recog  <- getWord16be
     unless (recog == 0) $ fail "Recognized != 0"
     strmId <- getWord16be
     digest <- getLazyByteString 4
     len    <- getWord16be
     unless (len <= (514 - 11)) $ fail "Length too long"
     case cmd of
       1 -> do addrport <- getLazyByteStringNul
               (ok4, ok6, pref6) <- parseFlags <$> getWord32be
               (addr, port) <- parseAddrPort addrport
               return (digest, RelayBegin strmId addr port ok4 ok6 pref6)
       2 -> do bstr <- getLazyByteString (fromIntegral len)
               return (digest, RelayData strmId bstr)
       3 -> do rsn <- getRelayEndReason len
               return (digest, RelayEnd strmId rsn)
       4 -> do ip4addr <- getLazyByteString 4
               if BS.any (/= 0) ip4addr
                  then do ttl <- getWord32be
                          let addr = IP4 (ip4ToString ip4addr)
                          return (digest, RelayConnected strmId addr ttl)
                  else do atype <- getWord8
                          unless (atype == 1) $
                            fail ("Bad address type: " ++ show atype)
                          ip6ad <- ip6ToString <$> getLazyByteString 16
                          ttl <- getWord32be
                          return (digest, RelayConnected strmId (IP6 ip6ad) ttl)
       5 -> return (digest, RelaySendMe strmId)
       6 -> do addr <- (IP4 . ip4ToString) <$> getLazyByteString 4
               port <- getWord16be
               skin <- getLazyByteString (128 + 16 + 42) -- TAP_C_HANDSHAKE_LEN
               idfp <- getLazyByteString 20 -- HASH_LEN
               return (digest, RelayExtend strmId addr port skin idfp)
       7 -> do edata <- getLazyByteString (128 + 20)
               return (digest, RelayExtended strmId edata)
       8 -> return (digest, RelayTruncate strmId)
       9 -> do rsn <- getDestroyReason
               return (digest, RelayTruncated strmId rsn)
       10 -> return (digest, RelayDrop strmId)
       11 -> do bstr <- getLazyByteStringNul
                return (digest, RelayResolve strmId (unpack bstr))
       12 -> do bstr <- getLazyByteString (fromIntegral len)
                case runGetOrFail getResolved bstr of
                  Left (_, _, str) -> fail str
                  Right (_, _, x)  ->
                    return (digest, RelayResolved strmId x)
       13 -> return (digest, RelayBeginDir strmId)
       14 -> do nspec <- getWord8
                specs <- replicateM (fromIntegral nspec) getExtendSpec
                htype <- getWord16be
                hlen  <- getWord16be
                hdata <- getLazyByteString (fromIntegral hlen)
                return (digest, RelayExtend2 strmId specs htype hdata)
       15 -> do hlen  <- getWord16be
                hdata <- getLazyByteString (fromIntegral hlen)
                return (digest, RelayExtended2 strmId hdata)
       32 -> do kl <- getWord16be
                pk <- getLazyByteString (fromIntegral kl)
                hs <- getLazyByteString 20
                sig <- getLazyByteString (fromIntegral kl) -- FIXME: correct?
                return (digest, RelayEstablishIntro strmId pk hs sig)
       33 -> do rc <- getLazyByteString 20
                return (digest, RelayEstablishRendezvous strmId rc)
       34 -> do pkId <- getLazyByteString 20
                bs   <- getLazyByteString (fromIntegral len - 20)
                return (digest, RelayIntroduce1 strmId pkId bs)
       35 -> do bs <- getLazyByteString (fromIntegral len)
                return (digest, RelayIntroduce2 strmId bs)
       36 -> do rc <- getLazyByteString 20
                gy <- getLazyByteString 128
                kh <- getLazyByteString 20
                return (digest, RelayRendezvous1 strmId rc gy kh)
       37 -> do gy <- getLazyByteString 128
                kh <- getLazyByteString 20
                return (digest, RelayRendezvous2 strmId gy kh)
       38 -> return (digest, RelayIntroEstablished strmId)
       39 -> return (digest, RelayRendezvousEstablished strmId)
       40 -> return (digest, RelayIntroduceAck strmId)
       _  -> fail ("Unknown command: " ++ show cmd)
 where
  getResolved =
    do done <- isEmpty
       if done
          then return []
          else do addr <- getTorAddress
                  ttl  <- getWord32be
                  ((addr, ttl) :) <$> getResolved

-- -----------------------------------------------------------------------------

renderRelayCell :: SHA1State -> RelayCell ->
                   (ByteString, SHA1State)
renderRelayCell state cell = (result, state')
 where
  emptyDigest = BS.pack [0,0,0,0]
  base        = runPut (putRelayCell emptyDigest cell)
  state'      = advanceSHA1State state base
  digest      = finalizeSHA1State state'
  result      = injectRelayHash (BS.take 4 digest) base

parseRelayCell :: SHA1State -> Get (RelayCell, SHA1State)
parseRelayCell state =
  do chunk <- getLazyByteString 509 -- PAYLOAD_LEN
     case runGetOrFail getRelayCell chunk of
       Left  (_, _, err) -> fail err
       Right (_, _, (digestStart, c)) ->
         do let noDigestBody = injectRelayHash (BS.replicate 4 0) chunk
                state'       = advanceSHA1State state noDigestBody
                fullDigest   = finalizeSHA1State state'
            unless (BS.take 4 fullDigest == digestStart) $
              fail "Relay cell digest mismatch."
            return (c, state')

injectRelayHash :: ByteString -> ByteString -> ByteString
injectRelayHash digest base =
  BS.take 5 base   `BS.append`
  BS.take 4 digest `BS.append`
  BS.drop 9 base

-- -----------------------------------------------------------------------------

putRelayCell :: ByteString -> RelayCell -> Put
putRelayCell dgst x =
  do let (cmd, bstr) = runPutM (putRelayCellGuts x)
         bstrinf = bstr `BS.append` BS.repeat 0
     putWord8          cmd
     putWord16be       0
     putWord16be       (relayStreamId x)
     putLazyByteString dgst
     putWord16be       (fromIntegral (BS.length bstr))
     unless (BS.length bstr <= (509 - 11)) $
       fail "RelayCell payload is too large!"
     putLazyByteString (BS.take (509 - 11) bstrinf) -- PAYLOAD_LEN-11

putRelayCellGuts :: RelayCell -> PutM Word8
putRelayCellGuts x@RelayBegin{} =
  do let str = unTorAddress (relayBeginAddress x) ++ ":" ++
               show (relayBeginPort x)
     putLazyByteString (pack str)
     putWord8 0
     putWord32be (renderFlags (relayBeginIPv4OK x) (relayBeginIPv6OK x)
                              (relayBeginIPv6Pref x))
     return 1
putRelayCellGuts x@RelayData{} =
  do putLazyByteString (relayData x)
     return 2
putRelayCellGuts x@RelayEnd{} =
  do putRelayEndReason (relayEndReason x)
     return 3
putRelayCellGuts x@RelayConnected{} =
  do case relayConnectedAddr x of
       IP6 _ -> do putWord32be 0
                   putWord8    1
       _     -> return ()
     putLazyByteString (torAddressByteString (relayConnectedAddr x))
     putWord32be (relayConnectedTTL x)
     return 4
putRelayCellGuts   RelaySendMe{} =
  return 5
putRelayCellGuts x@RelayExtend{} =
  do putLazyByteString (torAddressByteString (relayExtendAddress x))
     putWord16be       (relayExtendPort x)
     putLazyByteString (relayExtendSkin x)
     putLazyByteString (relayExtendIdent x)
     return 6
putRelayCellGuts x@RelayExtended{} =
  do putLazyByteString (relayExtendedData x)
     return 7
putRelayCellGuts   RelayTruncate{} =
  return 8
putRelayCellGuts x@RelayTruncated{} =
  do putDestroyReason (relayTruncatedRsn x)
     return 9
putRelayCellGuts   RelayDrop{} =
  return 10
putRelayCellGuts x@RelayResolve{} =
  do putLazyByteString (pack (relayResolveName x))
     putWord8 0
     return 11
putRelayCellGuts x@RelayResolved{} =
  do forM_ (relayResolvedAddrs x) $ \ (addr, ttl) ->
       do putTorAddress addr
          putWord32be   ttl
     return 12
putRelayCellGuts   RelayBeginDir{} =
  return 13
putRelayCellGuts x@RelayExtend2{} =
  do putWord8 (fromIntegral (length (relayExtendTarget x)))
     forM_ (relayExtendTarget x) putExtendSpec
     putWord16be (relayExtendType x)
     putWord16be (fromIntegral (BS.length (relayExtendData x)))
     putLazyByteString (relayExtendData x)
     return 14
putRelayCellGuts x@RelayExtended2{} =
  do putWord16be (fromIntegral (BS.length (relayExtendedData x)))
     putLazyByteString (relayExtendedData x)
     return 15
putRelayCellGuts x@RelayEstablishIntro{} =
  do putWord16be (fromIntegral (BS.length (relayEstIntKey x)))
     -- FIXME: Put guards on these sizes
     putLazyByteString (relayEstIntKey x)
     putLazyByteString (relayEstIntSessHash x)
     putLazyByteString (relayEstIntSig x)
     return 32
putRelayCellGuts x@RelayEstablishRendezvous{} =
     -- FIXME: Put guards on these sizes
  do putLazyByteString (relayEstRendCookie x)
     return 33
putRelayCellGuts x@RelayIntroduce1{} =
     -- FIXME: Put guards on these sizes
  do putLazyByteString (relayIntro1KeyId x)
     putLazyByteString (relayIntro1Data x)
     return 34
putRelayCellGuts x@RelayIntroduce2{} =
     -- FIXME: Put guards on these sizes
  do putLazyByteString (relayIntro2Data x)
     return 35
putRelayCellGuts x@RelayRendezvous1{} =
     -- FIXME: Put guards on these sizes
  do putLazyByteString (relayRendCookie x)
     putLazyByteString (relayRendGY x)
     putLazyByteString (relayRendKH x)
     return 36
putRelayCellGuts x@RelayRendezvous2{} =
     -- FIXME: Put guards on these sizes
  do putLazyByteString (relayRendGY x)
     putLazyByteString (relayRendKH x)
     return 37
putRelayCellGuts   RelayIntroEstablished{} =
  return 38
putRelayCellGuts   RelayRendezvousEstablished{} =
  return 39
putRelayCellGuts   RelayIntroduceAck{} =
  return 40

-- -----------------------------------------------------------------------------

parseFlags :: Word32 -> (Bool, Bool, Bool)
parseFlags x = (not (testBit x 1), testBit x 0, testBit x 2)

renderFlags :: Bool -> Bool -> Bool -> Word32
renderFlags ip4ok ip6ok ip6pref = ip4bit .|. ip6bit .|. ip6prefbit
 where
  ip4bit     = if ip4ok   then 0     else bit 1
  ip6bit     = if ip6ok   then bit 0 else 0
  ip6prefbit = if ip6pref then bit 2 else 0

parseAddrPort :: ByteString -> Get (TorAddress, Word16)
parseAddrPort bstr =
  case parse addrPort bstr of
    Data.Attoparsec.ByteString.Lazy.Fail _ _ err -> fail err
    Data.Attoparsec.ByteString.Lazy.Done _   res -> return res
 where
  addrPort =
    do addr <- addrPart
       _    <- char8 ':'
       port <- decimalNum (const True)
       return (addr, port)
  addrPart = ip4Addr <|> ip6Addr <|> hostnameAddr
  ip4Addr  = IP4 <$> ip4
  ip6Addr  = do x <- ip6
                return (IP6 ("[" ++ x ++ "]"))
  hostnameAddr = (Hostname . toString) <$> many1 (notWord8 58)

-- -----------------------------------------------------------------------------

data RelayEndReason = ReasonMisc
                    | ReasonResolveFailed
                    | ReasonConnectionRefused
                    | ReasonExitPolicy ByteString Word32
                    | ReasonDestroyed
                    | ReasonDone
                    | ReasonTimeout
                    | ReasonNoRoute
                    | ReasonHibernating
                    | ReasonInternal
                    | ReasonResourceLimit
                    | ReasonConnectionReset
                    | ReasonTorProtocol
                    | ReasonNotDirectory
 deriving (Eq, Show)

getRelayEndReason :: Word16 -> Get RelayEndReason
getRelayEndReason len =
  do b <- getWord8
     case b of
       1  -> return ReasonMisc
       2  -> return ReasonResolveFailed
       3  -> return ReasonConnectionRefused
       -- FIXME: Turn these into better data structures.
       4 | len == 9  -> do addr <- getLazyByteString 4
                           ttl  <- getWord32be
                           return (ReasonExitPolicy addr ttl)
         | len == 21 -> do addr <- getLazyByteString 16
                           ttl <- getWord32be
                           return (ReasonExitPolicy addr ttl)
         | otherwise -> fail ("Bad length for REASON_EXITPOLICY: " ++ show len)
       5  -> return ReasonDestroyed
       6  -> return ReasonDone
       7  -> return ReasonTimeout
       8  -> return ReasonNoRoute
       9  -> return ReasonHibernating
       10 -> return ReasonInternal
       11 -> return ReasonResourceLimit
       12 -> return ReasonConnectionReset
       13 -> return ReasonTorProtocol
       14 -> return ReasonNotDirectory
       _  -> fail ("Unknown destroy reason: " ++ show b)

putRelayEndReason :: RelayEndReason -> Put
putRelayEndReason ReasonMisc              = putWord8 1
putRelayEndReason ReasonResolveFailed     = putWord8 2
putRelayEndReason ReasonConnectionRefused = putWord8 3
putRelayEndReason (ReasonExitPolicy a t)  =
  do putWord8 4
     putLazyByteString a
     putWord32be t
putRelayEndReason ReasonDestroyed             = putWord8 5
putRelayEndReason ReasonDone                = putWord8 6
putRelayEndReason ReasonTimeout             = putWord8 7
putRelayEndReason ReasonNoRoute             = putWord8 8
putRelayEndReason ReasonHibernating         = putWord8 9
putRelayEndReason ReasonInternal            = putWord8 10
putRelayEndReason ReasonResourceLimit       = putWord8 11
putRelayEndReason ReasonConnectionReset     = putWord8 12
putRelayEndReason ReasonTorProtocol         = putWord8 13
putRelayEndReason ReasonNotDirectory        = putWord8 14

-- -----------------------------------------------------------------------------

data ExtendSpec = ExtendIP4    ByteString Word16
                | ExtendIP6    ByteString Word16
                | ExtendDigest ByteString
 deriving (Eq, Show)

putExtendSpec :: ExtendSpec -> Put
putExtendSpec (ExtendIP4 addr port) =
  do putWord8          0x00
     putWord8          (4 + 2)
     putLazyByteString addr
     putWord16be       port
putExtendSpec (ExtendIP6 addr port) =
  do putWord8          0x01
     putWord8          (16 + 2)
     putLazyByteString addr
     putWord16be       port
putExtendSpec (ExtendDigest hash) =
  do putWord8          0x02
     putWord8          20
     putLazyByteString hash

getExtendSpec :: Get ExtendSpec
getExtendSpec =
  do lstype <- getWord8
     lslen  <- getWord8
     case (lstype, lslen) of
       (0x00,  6) -> do addr <- getLazyByteString 4
                        port <- getWord16be
                        return (ExtendIP4 addr port)
       (0x01, 18) -> do addr <- getLazyByteString 16
                        port <- getWord16be
                        return (ExtendIP6 addr port)
       (0x02, 20) -> do hash <- getLazyByteString 20
                        return (ExtendDigest hash)
       (_,     _) -> fail "Invalid LSTYPE / LSLEN combination."


