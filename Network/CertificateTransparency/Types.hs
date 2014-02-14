module Network.CertificateTransparency.Types where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.X509
import Data.Word

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
    } deriving Show

data LogEntryDb = LogEntryDb
    { logEntryDbCert :: ByteString
    }

data LogEntries = LogEntries
    { logEntriesEntries :: [LogEntry]
    } deriving Show

data MerkleTreeLeaf = MerkleTreeLeaf
    { version :: Version
    , leafType :: MerkleLeafType
    , timestampedEntry :: TimestampedEntry
    } deriving Show
data MerkleTreeLeaf' = MerkleTreeLeaf'
    { version' :: Version
    , leafType' :: MerkleLeafType
    , timestampedEntry' :: TimestampedEntry'
    } deriving Show
    

type MerkleLeafType = Word8
type Version = Word8
data LogEntryType = X509Entry | PrecertEntry deriving Show
data TimestampedEntry = TimestampedEntry
    { timestamp' :: Word64
    , entryType :: LogEntryType
    , cert :: Cert
    } deriving Show
data TimestampedEntry' = TimestampedEntry'
    { timestamp'' :: Word64
    , entryType' :: LogEntryType
    , cert' :: Cert'
    } deriving Show

data Cert = ASN1Cert Certificate
          | PreCert LBS.ByteString
          deriving Show

data Cert' = ASN1Cert' LBS.ByteString
           | PreCert' LBS.ByteString
           deriving Show
