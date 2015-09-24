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
    threadDelay $ currentTime*1000
    res <- catchAny action (\e -> logException e >> return False)
    let nextTime = if res then initial else backoffFunction currentTime
    repeat initial nextTime backoffFunction action

-- |Find the next log entry that we expect, query the log server
-- for that and the next 2000 log entries, and write those to the DB.
-- Returns whether the log server had new log entries.
syncLogEntriesForLog :: Connection -> LogServer -> IO Bool
syncLogEntriesForLog conn logServer = do
    debugM "sync" $ "Syncing " ++ show logServer

    start <- fmap (fromMaybe 0) $ nextLogServerEntryForLogServer conn logServer
    let end = start + 2000

    entries' <- getEntries logServer (start, end)
    case entries' of
        Just entries -> do
            let certs' = map extractCert entries
            abortIfAnyCertsFailedToParse certs'
            let certs = rights certs'

            mapM_ (insertCert conn) (map extractByteString certs)

            insertLogEntries conn (map (\(crt, i) ->
                        ( logServerId logServer
                        , i
                        , certToEntryType crt
                        , Binary . MD5.hashlazy . extractByteString $ crt))
                    (zip certs [start..end]))
            return True
        Nothing -> do
            debugM "sync" "No entries"
            return False

    where
        abortIfAnyCertsFailedToParse :: [Either (BSL.ByteString, ByteOffset, String) Cert'] -> IO ()
        abortIfAnyCertsFailedToParse certs = do
            let numOfCertsThatFailedToParse = length . lefts $ certs
            when (numOfCertsThatFailedToParse > 0) $ do
                errorM "sync" (show numOfCertsThatFailedToParse ++ " certificates returned by " ++ show logServer ++ " failed to be parsed as certificates by the X509 library: " ++ (show $ lefts $ certs))
                error "Exiting. A cert failing to parse needs manually intervention, such as raising a bug against the X509 library."



extractCert :: LogEntry -> Either (BSL.ByteString, ByteOffset, String) Cert'
extractCert logEntry = (\(_, _, m) -> cert' . timestampedEntry' $ m) <$> (B.decodeOrFail . BSL.pack . BS.unpack . logEntryLeafInput $ logEntry)

extractByteString :: Cert' -> BSL.ByteString
extractByteString (ASN1Cert' s) = s
extractByteString (PreCert' s) = s

certToEntryType :: Cert' -> Int
certToEntryType (ASN1Cert' _) = 0
certToEntryType (PreCert' _) = 1
