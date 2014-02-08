{-# LANGUAGE OverloadedStrings, TypeOperators #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Network.CertificateTransparency.Db
    ( logServers
    , nextLogServerEntryForLogServer
    , updateDomainOfLogEntry
    , lookupUnprocessedLogEntries
    , sthExists
    , insertSth
    , lookupKnownGoodSth
    , setSthToBeVerified
    , lookupUnverifiedSth
    ) where

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.FromRow
import Database.PostgreSQL.Simple.ToField
import Database.PostgreSQL.Simple.ToRow

import Network.CertificateTransparency.Types

updateDomainOfLogEntry :: Connection -> LogServer -> Int -> LogEntry -> String -> IO ()
updateDomainOfLogEntry conn ls idx le s = do
    let sql = "UPDATE log_entry SET domain = ? WHERE log_server_id = ? AND idx = ? AND leaf_input = ? and extra_data = ?"
    _ <- execute conn sql $ (s, logServerId ls, idx) :. le
    return ()

lookupUnprocessedLogEntries :: Connection -> LogServer -> IO [Only Int :. LogEntry]
lookupUnprocessedLogEntries conn logServer = do
    let sql = "SELECT idx, leaf_input, extra_data FROM log_entry WHERE log_server_id = ? AND domain is null ORDER BY idx asc LIMIT 100"
    query conn sql (Only $ logServerId logServer)

logServers :: Connection -> IO [LogServer]
logServers conn = withTransaction conn $ do
    let sql = "SELECT * FROM log_server"
    query_ conn sql :: IO [LogServer]

nextLogServerEntryForLogServer :: Connection -> LogServer -> IO Int
nextLogServerEntryForLogServer conn ls = do
    let sql = "SELECT max(idx)+1 FROM log_entry WHERE log_server_id = ?"
    result <- query conn sql (Only $ logServerId ls) :: IO [Only Int]
    return $ only $ head $ result

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
    fromRow = LogEntry <$> field <*> field

instance ToRow LogEntry where
    toRow d = [ toField (Binary $ logEntryLeafInput d)
              , toField (Binary $ logEntryExtraData d)
              ]

