{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.CertificateTransparency.Parser where

import Control.Monad
import Data.Aeson
import qualified Data.ByteString.Base64 as B64
import Network.CertificateTransparency.Types
import qualified Data.ByteString.Char8 as BC8

instance FromJSON SignedTreeHead where
    parseJSON (Object v) = SignedTreeHead <$>
                            v .: "tree_size" <*>
                            v .: "timestamp" <*>
                            liftM (B64.decodeLenient . BC8.pack) (v .: "sha256_root_hash") <*>
                            liftM (BC8.pack) (v .: "tree_head_signature")
    parseJSON _          = mzero

instance FromJSON ConsistencyProof where
    parseJSON (Object v) = ConsistencyProof <$>
                            liftM (map (B64.decodeLenient . BC8.pack)) (v .: "consistency")
    parseJSON _          = mzero

instance FromJSON LogEntry where
    parseJSON (Object v) = LogEntry <$>
                            liftM (B64.decodeLenient . BC8.pack) (v .: "leaf_input")
    parseJSON _          = mzero

instance FromJSON LogEntries where
    parseJSON (Object v) = LogEntries <$>
                            v .: "entries"
    parseJSON _          = mzero
