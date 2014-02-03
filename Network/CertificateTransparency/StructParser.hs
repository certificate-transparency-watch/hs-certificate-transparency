{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.CertificateTransparency.StructParser
    (
    ) where

import Control.Applicative
import qualified Data.Binary as B
import Data.Binary.Get
import Data.Word

import Network.CertificateTransparency.Types

instance B.Binary MerkleTreeLeaf' where
    get = MerkleTreeLeaf' <$> B.get <*> B.get <*> B.get
    put = undefined

instance B.Binary TimestampedEntry' where
    get = do
        ts <- B.get
        et <- B.get

        a <- B.get :: B.Get Word8
        b <- B.get :: B.Get Word8
        c <- B.get :: B.Get Word8
        let length = 2^16 * (fromIntegral a) + 2^8 * (fromIntegral b) + (fromIntegral c)

        c <- getLazyByteString length

        return $ TimestampedEntry' ts et c

    put = undefined
