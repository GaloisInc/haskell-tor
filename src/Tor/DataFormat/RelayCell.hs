{-# LANGUAGE DeriveDataTypeable #-}
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
import Control.Exception
import Control.Monad
import Crypto.Hash
import Data.Attoparsec.ByteString
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteArray(convert)
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8(pack,unpack)
import Data.ByteString.Lazy(toStrict,fromStrict)
import Data.Typeable
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
     digest <- getByteString 4
     len    <- getWord16be
     unless (len <= (514 - 11)) $ fail "Length too long"
     case cmd of
       1 -> do addrport <- toStrict <$> getLazyByteStringNul
               (ok4, ok6, pref6) <- parseFlags <$> getWord32be
               (addr, port) <- parseAddrPort addrport
               return (digest, RelayBegin strmId addr port ok4 ok6 pref6)
       2 -> do bstr <- getByteString (fromIntegral len)
               return (digest, RelayData strmId bstr)
       3 -> do rsn <- getRelayEndReason len
               return (digest, RelayEnd strmId rsn)
       4 -> do ip4addr <- getByteString 4
               if BS.any (/= 0) ip4addr
                  then do ttl <- getWord32be
                          let addr = IP4 (ip4ToString ip4addr)
                          return (digest, RelayConnected strmId addr ttl)
                  else do atype <- getWord8
                          unless (atype == 1) $
                            fail ("Bad address type: " ++ show atype)
                          ip6ad <- ip6ToString <$> getByteString 16
                          ttl <- getWord32be
                          return (digest, RelayConnected strmId (IP6 ip6ad) ttl)
       5 -> return (digest, RelaySendMe strmId)
       6 -> do addr <- (IP4 . ip4ToString) <$> getByteString 4
               port <- getWord16be
               skin <- getByteString (128 + 16 + 42) -- TAP_C_HANDSHAKE_LEN
               idfp <- getByteString 20 -- HASH_LEN
               return (digest, RelayExtend strmId addr port skin idfp)
       7 -> do edata <- getByteString (128 + 20)
               return (digest, RelayExtended strmId edata)
       8 -> return (digest, RelayTruncate strmId)
       9 -> do rsn <- getDestroyReason
               return (digest, RelayTruncated strmId rsn)
       10 -> return (digest, RelayDrop strmId)
       11 -> do bstr <- toStrict <$> getLazyByteStringNul
                return (digest, RelayResolve strmId (unpack bstr))
       12 -> do bstr <- getByteString (fromIntegral len)
                case runGetOrFail getResolved (fromStrict bstr) of
                  Left (_, _, str) -> fail str
                  Right (_, _, x)  ->
                    return (digest, RelayResolved strmId x)
       13 -> return (digest, RelayBeginDir strmId)
       14 -> do nspec <- getWord8
                specs <- replicateM (fromIntegral nspec) getExtendSpec
                htype <- getWord16be
                hlen  <- getWord16be
                hdata <- getByteString (fromIntegral hlen)
                return (digest, RelayExtend2 strmId specs htype hdata)
       15 -> do hlen  <- getWord16be
                hdata <- getByteString (fromIntegral hlen)
                return (digest, RelayExtended2 strmId hdata)
       32 -> do kl <- getWord16be
                pk <- getByteString (fromIntegral kl)
                hs <- getByteString 20
                sig <- getByteString (fromIntegral kl) -- FIXME: correct?
                return (digest, RelayEstablishIntro strmId pk hs sig)
       33 -> do rc <- getByteString 20
                return (digest, RelayEstablishRendezvous strmId rc)
       34 -> do pkId <- getByteString 20
                bs   <- getByteString (fromIntegral len - 20)
                return (digest, RelayIntroduce1 strmId pkId bs)
       35 -> do bs <- getByteString (fromIntegral len)
                return (digest, RelayIntroduce2 strmId bs)
       36 -> do rc <- getByteString 20
                gy <- getByteString 128
                kh <- getByteString 20
                return (digest, RelayRendezvous1 strmId rc gy kh)
       37 -> do gy <- getByteString 128
                kh <- getByteString 20
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

renderRelayCell :: Context SHA1 -> RelayCell ->
                   (ByteString, Context SHA1)
renderRelayCell state cell = (result, state')
 where
  emptyDigest = BS.pack [0,0,0,0]
  base        = toStrict (runPut (putRelayCell emptyDigest cell))
  state'      = hashUpdate state base
  digest      = hashFinalize state'
  result      = injectRelayHash (BS.take 4 (convert digest)) base

parseRelayCell :: Context SHA1 -> Get (RelayCell, Context SHA1)
parseRelayCell state =
  do chunk <- getByteString 509 -- PAYLOAD_LEN
     case runGetOrFail getRelayCell (fromStrict chunk) of
       Left  (_, _, err) -> fail err
       Right (_, _, (digestStart, c)) ->
         do let noDigestBody = injectRelayHash (BS.replicate 4 0) chunk
                state'       = hashUpdate state noDigestBody
                fullDigest   = convert (hashFinalize state')
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
     let bstr' = toStrict bstr
     putWord8          cmd
     putWord16be       0
     putWord16be       (relayStreamId x)
     putByteString     dgst
     putWord16be       (fromIntegral (BS.length bstr'))
     unless (BS.length bstr' <= (509 - 11)) $
       fail "RelayCell payload is too large!"
     putLazyByteString bstr
     putByteString     (BS.replicate ((509 - 11) - BS.length bstr') 0)

putRelayCellGuts :: RelayCell -> PutM Word8
putRelayCellGuts x@RelayBegin{} =
  do let str = unTorAddress (relayBeginAddress x) ++ ":" ++
               show (relayBeginPort x)
     putByteString     (pack str)
     putWord8 0
     putWord32be (renderFlags (relayBeginIPv4OK x) (relayBeginIPv6OK x)
                              (relayBeginIPv6Pref x))
     return 1
putRelayCellGuts x@RelayData{} =
  do putByteString     (relayData x)
     return 2
putRelayCellGuts x@RelayEnd{} =
  do putRelayEndReason (relayEndReason x)
     return 3
putRelayCellGuts x@RelayConnected{} =
  do case relayConnectedAddr x of
       IP6 _ -> do putWord32be 0
                   putWord8    1
       _     -> return ()
     putByteString     (torAddressByteString (relayConnectedAddr x))
     putWord32be (relayConnectedTTL x)
     return 4
putRelayCellGuts   RelaySendMe{} =
  return 5
putRelayCellGuts x@RelayExtend{} =
  do putByteString     (torAddressByteString (relayExtendAddress x))
     putWord16be       (relayExtendPort x)
     putByteString     (relayExtendSkin x)
     putByteString     (relayExtendIdent x)
     return 6
putRelayCellGuts x@RelayExtended{} =
  do putByteString     (relayExtendedData x)
     return 7
putRelayCellGuts   RelayTruncate{} =
  return 8
putRelayCellGuts x@RelayTruncated{} =
  do putDestroyReason (relayTruncatedRsn x)
     return 9
putRelayCellGuts   RelayDrop{} =
  return 10
putRelayCellGuts x@RelayResolve{} =
  do putByteString     (pack (relayResolveName x))
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
     putByteString     (relayExtendData x)
     return 14
putRelayCellGuts x@RelayExtended2{} =
  do putWord16be (fromIntegral (BS.length (relayExtendedData x)))
     putByteString     (relayExtendedData x)
     return 15
putRelayCellGuts x@RelayEstablishIntro{} =
  do putWord16be (fromIntegral (BS.length (relayEstIntKey x)))
     -- FIXME: Put guards on these sizes
     putByteString     (relayEstIntKey x)
     putByteString     (relayEstIntSessHash x)
     putByteString     (relayEstIntSig x)
     return 32
putRelayCellGuts x@RelayEstablishRendezvous{} =
     -- FIXME: Put guards on these sizes
  do putByteString     (relayEstRendCookie x)
     return 33
putRelayCellGuts x@RelayIntroduce1{} =
     -- FIXME: Put guards on these sizes
  do putByteString     (relayIntro1KeyId x)
     putByteString     (relayIntro1Data x)
     return 34
putRelayCellGuts x@RelayIntroduce2{} =
     -- FIXME: Put guards on these sizes
  do putByteString     (relayIntro2Data x)
     return 35
putRelayCellGuts x@RelayRendezvous1{} =
     -- FIXME: Put guards on these sizes
  do putByteString     (relayRendCookie x)
     putByteString     (relayRendGY x)
     putByteString     (relayRendKH x)
     return 36
putRelayCellGuts x@RelayRendezvous2{} =
     -- FIXME: Put guards on these sizes
  do putByteString     (relayRendGY x)
     putByteString     (relayRendKH x)
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
    Data.Attoparsec.ByteString.Fail _ _ err -> fail err
    Data.Attoparsec.ByteString.Partial f    ->
     case f BS.empty of
       Data.Attoparsec.ByteString.Fail _ _ err -> fail err
       Data.Attoparsec.ByteString.Done _   res -> return res
    Data.Attoparsec.ByteString.Done _   res -> return res
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
                    | ReasonExitPolicy TorAddress Word32
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
 deriving (Eq, Show, Typeable)

instance Exception RelayEndReason

getRelayEndReason :: Word16 -> Get RelayEndReason
getRelayEndReason len =
  do b <- getWord8
     case b of
       1  -> return ReasonMisc
       2  -> return ReasonResolveFailed
       3  -> return ReasonConnectionRefused
       -- FIXME: Turn these into better data structures.
       4 | len == 9  -> do addr <- (IP4 . ip4ToString) <$> getByteString 4
                           ttl  <- getWord32be
                           return (ReasonExitPolicy addr ttl)
         | len == 21 -> do addr <- (IP6 . ip6ToString) <$> getByteString 16
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
     putByteString     (torAddressByteString a)
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
     putByteString     addr
     putWord16be       port
putExtendSpec (ExtendIP6 addr port) =
  do putWord8          0x01
     putWord8          (16 + 2)
     putByteString     addr
     putWord16be       port
putExtendSpec (ExtendDigest hash) =
  do putWord8          0x02
     putWord8          20
     putByteString     hash

getExtendSpec :: Get ExtendSpec
getExtendSpec =
  do lstype <- getWord8
     lslen  <- getWord8
     case (lstype, lslen) of
       (0x00,  6) -> do addr <- getByteString 4
                        port <- getWord16be
                        return (ExtendIP4 addr port)
       (0x01, 18) -> do addr <- getByteString 16
                        port <- getWord16be
                        return (ExtendIP6 addr port)
       (0x02, 20) -> do hash <- getByteString 20
                        return (ExtendDigest hash)
       (_,     _) -> fail "Invalid LSTYPE / LSLEN combination."


