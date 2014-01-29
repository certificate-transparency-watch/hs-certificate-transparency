module Network.CertificateTransparency.Types where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Certificate.X509
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
    , logEntryExtraData :: ByteString
    } deriving Show

data LogEntries = LogEntries
    { logEntriesEntries :: [LogEntry]
    } deriving Show

data MerkleTreeLeaf = MerkleTreeLeaf
    { version :: Version
    , leafType :: MerkleLeafType
    , timestampedEntry :: TimestampedEntry
    } deriving Show
    

type MerkleLeafType = Word8
type Version = Word8
type LogEntryType = Word16
data TimestampedEntry = TimestampedEntry
    { timestamp' :: Word64
    , entryType :: LogEntryType
    , cert :: Cert
    } deriving Show

data Cert = ASN1Cert Certificate deriving Show
