{-# LANGUAGE Safe #-}
module Network.CertificateTransparency.Types where

import Data.ByteString (ByteString)

data SignedTreeHead = SignedTreeHead
    { treeSize :: Int
    , timestamp :: Int
    , rootHash :: ByteString
    , treeHeadSignature :: ByteString
    } deriving Show

data ConsistencyProof = ConsistencyProof
    { proofCP :: [ByteString]
    } deriving Show

data LogServer = LogServer
    { logServerId :: Int
    , logServerPrefix :: String
    , logServerName :: String
    } deriving Show

data LogEntry = LogEntry
    { logEntryLeafInput :: ByteString
    , logEntryExtraData :: ByteString
    } deriving Show

data LogEntries = LogEntries
    { logEntriesEntries :: [LogEntry]
    } deriving Show
