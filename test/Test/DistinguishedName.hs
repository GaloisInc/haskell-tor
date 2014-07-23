module Test.DistinguishedName(distinguishedNameTests) where

import Control.Applicative
import Control.Monad
import Data.ASN1.OID
import Data.X509
import Data.String
import Test.Framework
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.Standard
import TLS.Certificate.DistinguishedName

newtype ReadableStr = ReadableStr { unReadableStr :: String }

instance Show ReadableStr where
  show = show . unReadableStr

instance Arbitrary ReadableStr where
  arbitrary =
    do len <- choose (1, 256)
       str <- replicateM len (elements printableChars)
       return (ReadableStr str)
   where printableChars = ['a'..'z'] ++ ['A'..'Z'] ++ ['_','.',' ']

instance Arbitrary DistinguishedName where
  arbitrary =
    do cn <- unReadableStr <$> arbitrary
       co <- unReadableStr <$> arbitrary
       og <- unReadableStr <$> arbitrary
       ou <- unReadableStr <$> arbitrary
       return (DistinguishedName [
                 (getObjectID DnCommonName,       fromString cn)
               , (getObjectID DnCountry,          fromString co)
               , (getObjectID DnOrganization,     fromString og)
               , (getObjectID DnOrganizationUnit, fromString ou)
               ])

prop_dnSerializes :: DistinguishedName -> Bool
prop_dnSerializes = serialProp getDistinguishedName putDistinguishedName

distinguishedNameTests :: Test
distinguishedNameTests =
  testProperty "DistinguishedName serializes" prop_dnSerializes

