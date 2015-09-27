{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.CertificateTransparency.StructParser
    (
    ) where

import qualified Data.ByteString.Lazy as LBS
import qualified Data.Binary as B
import Data.Binary.Get
import Data.Int
import Data.Word

import Network.CertificateTransparency.Types

instance B.Binary MerkleTreeLeaf' where
    get = MerkleTreeLeaf' <$> B.get <*> B.get <*> B.get
    put = undefined

instance B.Binary LogEntryType where
    get = do
        x <- B.get :: Get Word16
        return $ case x of
            0 -> X509Entry
            1 -> PrecertEntry
            u -> error $ "unrecognised LogEntryType " ++ show u
    put = undefined

instance B.Binary TimestampedEntry' where
    get = do
        ts <- B.get
        et <- B.get

        case et of
            X509Entry -> do
                c <- getVariableLengthMember
                return $ TimestampedEntry' ts et (ASN1Cert' c)
            PrecertEntry -> do
                _ <- getLazyByteString 32
                c <- getVariableLengthMember
                return $ TimestampedEntry' ts et (PreCert' c)

    put = undefined


getVariableLengthMember :: Get LBS.ByteString
getVariableLengthMember =  do
    len <- getWord24
    getLazyByteString len

getWord24 :: Get Int64
getWord24 = do
    a <- B.get :: B.Get Word8
    b <- B.get :: B.Get Word8
    c <- B.get :: B.Get Word8
    return $ 2^16 * (fromIntegral a) + 2^8*(fromIntegral b) + (fromIntegral c)
    
