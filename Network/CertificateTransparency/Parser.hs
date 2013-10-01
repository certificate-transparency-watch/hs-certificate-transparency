{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.CertificateTransparency.Parser where

import Control.Applicative ((<*>), (<$>))
import Control.Monad
import Data.Aeson
import qualified Data.ByteString.Base64 as B64
import Network.CertificateTransparency.Types

instance FromJSON SignedTreeHead where
    parseJSON (Object v) = SignedTreeHead <$>
                            v .: "tree_size" <*>
                            v .: "timestamp" <*>
                            liftM B64.decodeLenient (v .: "sha256_root_hash") <*>
                            v .: "tree_head_signature"
    parseJSON _          = mzero

instance FromJSON ConsistencyProof where
    parseJSON (Object v) = ConsistencyProof <$>
                            liftM (map B64.decodeLenient) (v .: "consistency")
    parseJSON _          = mzero
