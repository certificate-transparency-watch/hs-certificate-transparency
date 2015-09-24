{-# LANGUAGE OverloadedStrings, TypeOperators #-}

import qualified Crypto.Hash.MD5 as MD5

import Control.Concurrent (threadDelay, forkIO)
import Control.Concurrent.Async
import Control.Exception (SomeException)
import Control.Monad (forever, forM_, when)
import qualified Data.Binary as B
import Data.Binary.Get (ByteOffset)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Data.Either
import Data.Maybe
import Database.PostgreSQL.Simple
import Prelude hiding (repeat)
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.ProcessLogEntriesJob
import Network.CertificateTransparency.StructParser()
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import System.Log.Logger

connectInfo :: ConnectInfo
connectInfo = defaultConnectInfo {
    connectDatabase = "ct-watch"
  , connectUser = "docker"
  , connectPassword = "docker"
  , connectHost = "172.17.42.1"
}

main :: IO ()
main = do
    setupLogging
    _ <- forkIO . everySeconds 59 $ catchAny pollLogServersForSth logException
    _ <- forkIO . everySeconds 157 $ catchAny processSth logException
    _ <- forkIO . everySeconds 31 $ catchAny syncLogEntries logException
    _ <- forkIO . everySeconds 17 $ catchAny (processLogEntries connectInfo) logException
    forever $ threadDelay (10*1000*1000)

    where
        syncLogEntries :: IO ()
        syncLogEntries = do
            conn <- connect connectInfo
            servers <- logServers conn
            _ <- mapConcurrently (\s -> repeat 2 2 (*2) (syncLogEntriesForLog conn s)) servers
            close conn

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

        extractByteString (ASN1Cert' s) = s
        extractByteString (PreCert' s) = s

        certToEntryType :: Cert' -> Int
        certToEntryType (ASN1Cert' _) = 0
        certToEntryType (PreCert' _) = 1



        pollLogServersForSth :: IO ()
        pollLogServersForSth = do
            debugM "poller" "Polling..."
            conn <- connect connectInfo
            servers <- logServers conn
            mapM_ (pollLogServerForSth conn) servers
            close conn

        pollLogServerForSth :: Connection -> LogServer -> IO ()
        pollLogServerForSth conn logServer = do
            sth <- getSth logServer
            case sth of
                Just sth' -> withTransaction conn $ do
                    sthExists' <- sthExists conn sth'
                    if (not sthExists')
                        then insertSth conn sth' logServer >> return ()
                        else return ()
                Nothing   -> return ()


        processSth :: IO ()
        processSth = do
            debugM "processor" "Processing..."
            conn <- connect connectInfo
            logs <- logServers conn
            forM_ logs $ \log -> do
                knownGoodSth' <- lookupKnownGoodSth conn log
                case knownGoodSth' of
                    Nothing -> errorM "processing" $ "Log " ++ show log ++ " has no known good STH. Set one such record verified."
                    Just knownGoodSth -> do
                        sths <- lookupUnverifiedSth conn log
                        forM_ sths $ \sth -> do
                            maybeConsistencyProof <- getSthConsistency log knownGoodSth sth
                            if (isGood $ checkConsistencyProof knownGoodSth sth <$> maybeConsistencyProof)
                                then setSthToBeVerified conn sth
                                else errorM "processor" ("Unable to verify sth: " ++ show sth)

            close conn

        isGood :: Maybe Bool -> Bool
        isGood (Just b) = b
        isGood Nothing  = False

        everySeconds n a = forever $ a >> threadDelay (n*1000*1000)

        setupLogging :: IO ()
        setupLogging = do
            updateGlobalLogger rootLoggerName (setLevel DEBUG)
            infoM "main" "Logger started."

logException :: SomeException -> IO ()
logException e = errorM "processor" ("Exception: " ++ show e)

tryAny :: IO a -> IO (Either SomeException a)
tryAny action = withAsync action waitCatch

catchAny :: IO a -> (SomeException -> IO a) -> IO a
catchAny action onE = tryAny action >>= either onE return

repeat :: Int -> Int -> (Int -> Int) -> IO Bool -> IO Bool
repeat initial currentTime backoffFunction action = do
    threadDelay $ currentTime*1000
    res <- catchAny action (\e -> logException e >> return False)
    let nextTime = if res then initial else backoffFunction currentTime
    repeat initial nextTime backoffFunction action

extractCert :: LogEntry -> Either (BSL.ByteString, ByteOffset, String) Cert'
extractCert logEntry = (\(_, _, m) -> cert' . timestampedEntry' $ m) <$> (B.decodeOrFail . BSL.pack . BS.unpack . logEntryLeafInput $ logEntry)
