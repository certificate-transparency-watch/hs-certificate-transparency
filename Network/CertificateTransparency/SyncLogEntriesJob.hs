{-# LANGUAGE OverloadedStrings #-}

module Network.CertificateTransparency.SyncLogEntriesJob (
    syncLogEntries
) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Monad (when)
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.Binary as B
import Data.Binary.Get (ByteOffset)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Data.Maybe
import Database.PostgreSQL.Simple
import Data.Either
import Prelude hiding (repeat)
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.StructParser()
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Util
import System.Log.Logger

syncLogEntries :: ConnectInfo -> IO ()
syncLogEntries connectInfo = do
    conn <- connect connectInfo
    servers <- logServers conn
    _ <- mapConcurrently (\s -> repeat 2 2 (*2) (syncLogEntriesForLog conn s)) servers
    close conn

repeat :: Int -> Int -> (Int -> Int) -> IO Bool -> IO Bool
repeat initial currentTime backoffFunction action = do
    threadDelay $ currentTime*999
    res <- catchAny action (\e -> logException e >> return False)
    let nextTime = if res then initial else backoffFunction currentTime
    repeat initial nextTime backoffFunction action

syncLogEntriesForLog :: Connection -> LogServer -> IO Bool
syncLogEntriesForLog conn logServer = do
    debugM "sync" $ "Syncing " ++ show logServer
    start <- fmap (fromMaybe 0) $ nextLogServerEntryForLogServer conn logServer
    let end = start + 2000

    entries' <- getEntries logServer (start, end)
    case entries' of
        Just entries -> do
            let certs' = map extractCert entries
            when (not . null . lefts $ certs') (error . show . lefts $ certs')

            let certs = rights certs'

            mapM_ (insertCert conn) (map extractByteString certs)

            let parameters = map (\(cert, i) -> (logServerId logServer, i, certToEntryType cert, Binary . MD5.hashlazy . extractByteString $ cert)) $ zip certs [start..end]
            _ <- executeMany conn "INSERT INTO log_entry (log_server_id, idx, log_entry_type, cert_md5) VALUES (?, ?, ?, ?)" parameters
            return True
        Nothing -> debugM "sync" "No entries" >> return False

extractCert :: LogEntry -> Either (BSL.ByteString, ByteOffset, String) Cert'
extractCert logEntry = (\(_, _, m) -> cert' . timestampedEntry' $ m) <$> (B.decodeOrFail . BSL.pack . BS.unpack . logEntryLeafInput $ logEntry)

extractByteString :: Cert' -> BSL.ByteString
extractByteString (ASN1Cert' s) = s
extractByteString (PreCert' s) = s

certToEntryType :: Cert' -> Int
certToEntryType (ASN1Cert' _) = 0
certToEntryType (PreCert' _) = 1
