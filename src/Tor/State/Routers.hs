{-# LANGUAGE RecordWildCards   #-}
module Tor.State.Routers(
         RouterDB
       , RouterRestriction(..)
       , newRouterDatabase
       , findRouter
       , getRouter
       , meetsRestrictions
       )
 where

import Control.Concurrent
import Control.Monad
import Crypto.Hash.Easy
import Crypto.PubKey.RSA.KeyHash
import Crypto.PubKey.RSA.PKCS15
import Crypto.Random
import Data.Array
import Data.Bits
import Data.Serialize.Get
import Data.ByteString(ByteString,unpack)
import Data.Hourglass
import Data.Hourglass.Now
import Data.List
import qualified Data.Map.Strict as Map
import Data.Maybe
import Data.Word
import MonadLib
import Tor.DataFormat.Consensus
import Tor.DataFormat.TorAddress
import Tor.NetworkStack
import Tor.NetworkStack.Fetch
import Tor.RNG
import Tor.RouterDesc
import Tor.State.Directories

newtype RouterDB = RouterDB (MVar RouterDBVersion)

data RouterDBVersion = RDB {
       rdbRevision      :: Word
     , rdbRouters       :: Array Word RouterDesc
     }

data RouterRestriction = IsStable -- ^Marked with the Stable flag
                       | NotRouter RouterDesc -- ^Is not the given router
                       | NotTorAddr TorAddress -- ^Is not the given address
                       | ExitNode -- ^Is an exit node of some kind
                       | ExitNodeAllowing TorAddress Word16
                         -- ^Is an exit node that allows traffic to the given
                         -- address and port.

-- |Build a new router database. This database will return before it is fully
-- initialized, in order to make general start-up faster. This may mean that
-- some queries of the database will take longer upon initial loading, or when
-- the database is being refreshed periodicatly.
newRouterDatabase :: TorNetworkStack ls s ->
                     DirectoryDB -> (String -> IO ()) ->
                     IO RouterDB
newRouterDatabase ns ddb logMsg =
  do rdbMV <- newEmptyMVar
     _ <- forkIO (updateConsensus ns ddb logMsg rdbMV)
     return (RouterDB rdbMV)

-- |Find a router given its fingerprint.
findRouter :: RouterDB -> ByteString -> IO (Maybe RouterDesc)
findRouter (RouterDB routerDB) fprint =
  (find fingerprintEq . rdbRouters) `fmap` readMVar routerDB
 where
  fingerprintEq x = keyHash' sha256 (routerSigningKey x) == fprint

-- |Fetch a router matching the given restrictions. The restrictions list should
-- be thought of an "AND" with a default of True given the empty list. This
-- routine may take awhile to find a suitable entry if the restrictions are
-- cumbersome or if the database is being reloaded.
getRouter :: RouterDB -> [RouterRestriction] -> TorRNG ->
             IO (TorRNG, RouterDesc)
getRouter (RouterDB routerDB) restrictions rng =
  do curdb              <- readMVar routerDB
     let (_, entriesPossib) = bounds (rdbRouters curdb)
     loop (rdbRouters curdb) (entriesPossib + 1) rng
 where
  loop entries idxMod g =
    do let (randBS, g') = randomBytesGenerate 8 g
       randWord <- fromIntegral <$> runGetIO getWord64be randBS
       let v = entries ! (randWord `mod` idxMod)
       if v `meetsRestrictions` restrictions
         then return (g', v)
         else loop entries idxMod g'
  --
  runGetIO getter bstr =
    case runGet getter bstr of
      Left  _ -> fail "Cannot read 64-bit Word from 64 bytes ..."
      Right x -> return x

meetsRestrictions :: RouterDesc -> [RouterRestriction] -> Bool
meetsRestrictions _   []       = True
meetsRestrictions rtr (r:rest) =
  case r of
    IsStable | "Stable" `elem` routerStatus rtr  -> meetsRestrictions rtr rest
             | otherwise                         -> False
    NotRouter rdesc | rtr == rdesc               -> False
                    | otherwise                  -> meetsRestrictions rtr rest
    NotTorAddr taddr | isSameAddr taddr rtr      -> False
                     | otherwise                 -> meetsRestrictions rtr rest
    ExitNode | allowsExits (routerExitRules rtr) -> meetsRestrictions rtr rest
             | otherwise                         -> False
    ExitNodeAllowing a p
          | allowsExit (routerExitRules rtr) a p -> meetsRestrictions rtr rest
          | otherwise                            -> False
 where 
  isSameAddr (IP4 x) s = x == routerIPv4Address s
  isSameAddr (IP6 x) s = x `elem` map fst (routerAlternateORAddresses s)
  isSameAddr _       _ = False
  --
  allowsExits (ExitRuleReject AddrSpecAll PortSpecAll : _) = False
  allowsExits _ = True
  --
  allowsExit [] _ _ = True -- "if no rule matches, the address wil be accepted"
  allowsExit (ExitRuleAccept addrrule portrule : rrest) addr port
    | addrMatches addr addrrule && portMatches port portrule = True
    | otherwise = allowsExit rrest addr port
  allowsExit (ExitRuleReject addrrule portrule : rrest) addr port
    | addrMatches addr addrrule && portMatches port portrule = False
    | otherwise = allowsExit rrest addr port
  --
  portMatches _ PortSpecAll           = True
  portMatches p (PortSpecRange p1 p2) = (p >= p1) && (p <= p2)
  portMatches p (PortSpecSingle p')   = p == p'
  --
  addrMatches :: TorAddress -> AddrSpec -> Bool
  addrMatches (Hostname _)          _                     = False
  addrMatches (TransientError _)    _                     = False
  addrMatches (NontransientError _) _                     = False
  addrMatches _                     AddrSpecAll           = True
  addrMatches (IP4 addr)            (AddrSpecIP4 addr')   = addr == addr'
  addrMatches (IP4 addr)            (AddrSpecIP4Mask a m) = ip4in' addr a m
  addrMatches (IP4 addr)            (AddrSpecIP4Bits a b) = ip4in  addr a b
  addrMatches (IP4 _)               (AddrSpecIP6 _)       = False
  addrMatches (IP4 _)               (AddrSpecIP6Bits _ _) = False
  addrMatches (IP6 _)               (AddrSpecIP4 _)       = False
  addrMatches (IP6 _)               (AddrSpecIP4Mask _ _) = False
  addrMatches (IP6 _)               (AddrSpecIP4Bits _ _) = False
  addrMatches (IP6 addr)            (AddrSpecIP6 addr')   = addr `ip6eq` addr'
  addrMatches (IP6 addr)            (AddrSpecIP6Bits a b) = ip6in addr a b
  --
  ip4in' addr addr' mask =
     masked (unAddr IP4 addr) mask' == masked (unAddr IP4 addr') mask'
    where mask' = generateMaskFromMask mask
  ip4in  addr addr' bits =
     masked (unAddr IP4 addr) mask == masked (unAddr IP4 addr') mask
    where mask  = generateMaskFromBits bits 4
  ip6in  addr addr' bits =
     masked (unAddr IP6 addr) mask == masked (unAddr IP6 addr') mask
    where mask  = generateMaskFromBits bits 16
  ip6eq  addr1 addr2 = expandIPv6 addr1 == expandIPv6 addr2
  --
  unAddr b = unpack . torAddressByteString . b
  generateMaskFromMask x = unAddr IP4 x
  generateMaskFromBits :: Int -> Int -> [Word8]
  generateMaskFromBits bits len
    | len == 0  = []
    | bits == 0 = 0   : generateMaskFromBits bits       (len - 1)
    | bits >= 8 = 255 : generateMaskFromBits (bits - 8) (len - 1)
    | otherwise = (255 `shiftL` (8 - len)) : generateMaskFromBits 0 (len - 1)
  masked a m = zipWith xor a m
  expandIPv6 = unAddr IP6

-- |The thread that updates the consensus document over time.
updateConsensus :: TorNetworkStack ls s ->
                   DirectoryDB -> (String -> IO ()) ->
                   MVar RouterDBVersion ->
                   IO ()
updateConsensus ns ddb logMsg rdbMV = runUpdates =<< drgNew
 where
  runUpdates g =
    do (res, g') <- runStateT g (runExceptionT update)
       case res of
         Right () -> return ()
         Left err -> logMsg ("Issue updating consensus document: " ++ err)
       runUpdates g'
  --
  update :: ExceptionT String (StateT TorRNG IO) ()
  update =
    do logMsg' "String consensus document update."
       dir <- withRNG (\ g -> inBase (getRandomDirectory g ddb))
       logMsg' ("Using directory " ++ dirNickname dir ++ " for consensus.")
       let addr = dirAddress dir ; port = dirDirPort dir
       (census, sha1dig, sha256dig) <- fetch' addr port ConsensusDocument
       let sigs = conSignatures census
       forM_ (conAuthorities census) (inBase . addDirectory ns logMsg ddb)
       validSigs <- inBase (getValidSignatures ddb sha1dig sha256dig sigs)
       when (length validSigs < 5) $
         raise "Couldn't get at least 5 valid signantures on consensus."
       logMsg' ("Found enough valid signatures: " ++ intercalate ", " validSigs)
       rdtable <- fetch' addr port Descriptors
       let routers = filter goodRouter (conRouters census)
       let table' = mapMaybe (crossReference rdtable) routers
       logMsg' ("New router processing complete. " ++ show (length table') ++
                " of " ++ show (length routers) ++ " routers available.")
       oldRdb <- inBase (tryTakeMVar rdbMV)
       let rev = maybe 1 (succ . rdbRevision) oldRdb
           arr = listArray (0, fromIntegral (length table' - 1)) table'
       inBase (putMVar rdbMV (RDB rev arr))
       nextTime <- withRNG (return . computeNextTime census)
       logMsg' ("Will reload census at "++showTime nextTime)
       inBase $ waitUntil nextTime
       logMsg' "Consensus expired. Reloading."
  --
  crossReference rdtable rtr =
    case Map.lookup (rtrIdentity rtr) rdtable of
      Nothing -> Nothing
      Just d  -> Just d{ routerStatus = rtrStatus rtr }
  --
  fetch' :: Fetchable a =>
            String -> Word16 -> FetchItem ->
            ExceptionT String (StateT TorRNG IO) a
  fetch' a p d =
    do m <- inBase (fetch ns a p d)
       case m of
         Left err -> raise ("Couldn't get " ++ show d ++ ": " ++ err)
         Right x  -> return x
  --
  withRNG :: (TorRNG -> IO (a, TorRNG)) -> ExceptionT String (StateT TorRNG IO) a
  withRNG action =
    do g <- get
       (res, g') <- inBase (action g)
       set g'
       return res
  --
  logMsg' = inBase . logMsg
  --
  goodRouter r =
    let s = rtrStatus r
    in ("Valid" `elem` s) && ("Running" `elem` s) && ("Fast" `elem` s)
  showTime = timePrint [Format_Hour, Format_Text ':', Format_Minute]

getValidSignatures :: DirectoryDB -> ByteString -> ByteString ->
                      [(Bool, ByteString, ByteString, ByteString)] ->
                      IO [String]
getValidSignatures ddb sha1dig sha256dig sigs =
  catMaybes <$>
    (forM sigs $ \ (isSHA1, ident, _, sig) ->
       do mdir <- findDirectory ident ddb
          -- FIXME: Do something more useful in the failure cases?
          case mdir of
            Nothing -> return Nothing
            Just dir ->
              do let digest = if isSHA1 then sha1dig else sha256dig
                     key    = dirSigningKey dir
                 if verify noHash key digest sig
                   then return (Just (dirNickname dir))
                   else return Nothing)

computeNextTime :: DRG g =>
                   Consensus -> g ->
                   (DateTime, g)
computeNextTime consensus g = (timeAdd lowest diffAmt, g')
 where
  validAfter = conValidAfter consensus
  freshUntil = conFreshUntil consensus
  validUntil = conValidUntil consensus
  interval   = timeDiff freshUntil validAfter
  lowest     = timeAdd freshUntil (mulSeconds 0.75 interval)
  interval'  = timeDiff validUntil lowest
  highest    = timeAdd lowest (mulSeconds 0.875 interval')
  diff       = timeDiff highest lowest
  (bstr, g') = randomBytesGenerate 8 g
  Right amt  = runGet ((Seconds . fromIntegral)`fmap` getWord64be) bstr
  diffAmt    = amt `mod` diff
  --
  mulSeconds :: Double -> Seconds -> Seconds
  mulSeconds f (Seconds s) = Seconds (round (f * fromIntegral s)) 

waitUntil :: DateTime -> IO ()
waitUntil time =
  do now <- getCurrentTime
     if now > time
        then return ()
        else do threadDelay 100000 -- (5 * 60 * 1000000) -- 5 minutes
                waitUntil time
