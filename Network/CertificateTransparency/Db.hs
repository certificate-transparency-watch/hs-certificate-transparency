{-# LANGUAGE OverloadedStrings, RankNTypes, TypeOperators #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.CertificateTransparency.Db
    ( logServers
    , nextLogServerEntryForLogServer
    , updateDomainOfLogEntry
    , lookupUnprocessedLogEntries
    , insertCert
    , insertLogEntries
    , sthExists
    , insertSth
    , lookupKnownGoodSth
    , setSthToBeVerified
    , lookupUnverifiedSth
    ) where

import Control.Monad
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Base64 as B64
import Data.Maybe
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.FromRow
import Database.PostgreSQL.Simple.ToField
import Database.PostgreSQL.Simple.ToRow

import Network.CertificateTransparency.Types

insertLogEntries :: Connection -> [(Int, Int, Int, Binary BS.ByteString)] -> IO ()
insertLogEntries conn xs = do
    let sql = "INSERT INTO log_entry (log_server_id, idx, log_entry_type, cert_md5) VALUES (?, ?, ?, ?)"
    _ <- executeMany conn sql xs
    return ()

insertCert :: Connection -> BSL.ByteString -> IO ()
insertCert conn bs = do
    let hash = MD5.hashlazy bs

    let sql = "SELECT md5 FROM cert WHERE md5 = ?"
    results <- query conn sql $ (Only $ Binary $ hash) :: IO [Only BS.ByteString]

    if (null results)
        then do
            let iSql = "INSERT INTO cert (md5, certificate) VALUES (?, ?)"
            _ <- execute conn iSql $ (Binary hash, Binary bs)
            return ()
        else return ()

updateDomainOfLogEntry :: Connection -> LogServer -> Int -> String -> IO ()
updateDomainOfLogEntry conn ls idx s = do
    let sql = "UPDATE log_entry SET domain = ? WHERE log_server_id = ? AND idx = ?"
    _ <- execute conn sql $ (s, logServerId ls, idx)
    return ()

lookupUnprocessedLogEntries :: Connection -> LogServer -> IO [Only Int :. LogEntryDb]
lookupUnprocessedLogEntries conn logServer = do
    let sql = "SELECT idx, certificate FROM log_entry JOIN cert ON log_entry.cert_md5 = cert.md5 WHERE log_server_id = ? AND domain is null LIMIT 1000"
    query conn sql (Only $ logServerId logServer)

logServers :: Connection -> IO [LogServer]
logServers conn = withTransaction conn $ do
    let sql = "SELECT * FROM log_server"
    query_ conn sql :: IO [LogServer]

nextLogServerEntryForLogServer :: Connection -> LogServer -> IO (Maybe Int)
nextLogServerEntryForLogServer conn ls = do
    let sql = "SELECT max(idx)+1 FROM log_entry WHERE log_server_id = ?"
    result <- query conn sql (Only $ logServerId ls) :: IO [Only Int]
    return $ listToMaybe $ map only $ result

sthExists :: Connection -> SignedTreeHead -> IO Bool
sthExists conn sth = do
    let sql = "SELECT * FROM sth WHERE treesize = ? AND timestamp = ? AND roothash = ? AND treeheadsignature = ?"
    results <- query conn sql sth :: IO [SignedTreeHead :. (Bool, Int)]
    return $ not $ null results

insertSth :: Connection -> SignedTreeHead -> LogServer -> IO ()
insertSth conn sth ls = do
    execute conn "INSERT INTO sth (treesize, timestamp, roothash, treeheadsignature, log_server_id) VALUES (?, ?, ?, ?, ?)" (sth :. Only (logServerId ls)) >> return ()

lookupKnownGoodSth :: Connection -> LogServer -> IO (Maybe SignedTreeHead)
lookupKnownGoodSth conn ls = do
    knownGoodSth' <- query conn "SELECT * FROM sth WHERE verified = true AND log_server_id = ? ORDER BY timestamp LIMIT 1" (Only $ logServerId ls) :: IO ([SignedTreeHead :. (Bool, Int)])
    return $ if (null knownGoodSth')
        then Nothing
        else Just $ first $ head knownGoodSth'

setSthToBeVerified :: Connection -> SignedTreeHead -> IO ()
setSthToBeVerified conn sth = do
    let updateSql = "UPDATE sth SET verified = true WHERE treesize = ? AND timestamp = ? AND roothash = ? AND treeheadsignature = ?"
    _ <- execute conn updateSql sth
    return ()

lookupUnverifiedSth :: Connection -> LogServer -> IO [SignedTreeHead]
lookupUnverifiedSth conn ls = do
    let sql = "SELECT * FROM sth WHERE verified = false AND log_server_id = ?"
    results <- query conn sql (Only $ logServerId ls) :: IO ([SignedTreeHead :. (Bool, Int)])
    return $ map first results


first :: (a :. b) -> a
first (a :. _) = a

only :: forall t. Only t -> t
only (Only a) = a

instance ToRow SignedTreeHead where
    toRow d = [ toField (treeSize d)
              , toField (timestamp d)
              , toField (B64.encode $ rootHash d)
              , toField (B64.encode $ treeHeadSignature d)
              ]

instance FromRow SignedTreeHead where
    fromRow = SignedTreeHead <$> field <*> field <*> (liftM B64.decodeLenient field) <*> (liftM B64.decodeLenient field)

instance FromRow LogServer where
     fromRow = LogServer <$> field <*> field <*> field

instance FromRow LogEntry where
    fromRow = LogEntry <$> field

instance FromRow LogEntryDb where
    fromRow = LogEntryDb <$> field
