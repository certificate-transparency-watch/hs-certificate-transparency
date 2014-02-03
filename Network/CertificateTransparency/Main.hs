{-# LANGUAGE OverloadedStrings, TypeOperators #-}

import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Base64.Lazy as B64L

import Control.Applicative ((<$>), (<*>))
import Control.Concurrent (threadDelay, forkIO)
import Control.Concurrent.Async
import Control.Exception (SomeException)
import qualified Control.Exception as E
import Control.Monad (forever, forM_, liftM)
import Data.ASN1.Types (ASN1Error)
import qualified Data.Binary as B
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Data.Certificate.X509
import Database.PostgreSQL.Simple
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.StructParser
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
    _ <- forkIO . everyMinute $ catchAny pollLogServersForSth logException
    _ <- forkIO . everyMinute $ catchAny processSth logException
    _ <- forkIO . everySeconds 20 $ catchAny syncLogEntries logException
    forever $ threadDelay (10*1000*1000)

    where
        syncLogEntries :: IO ()
        syncLogEntries = do
            conn <- connect connectInfo
            servers <- logServers conn
            mapM_ (syncLogEntriesForLog conn) servers
            close conn

        only (Only a) = a

        syncLogEntriesForLog :: Connection -> LogServer -> IO ()
        syncLogEntriesForLog conn logServer = do
            debugM "sync" $ "Syncing " ++ show logServer
            let sql = "SELECT max(idx)+1 FROM log_entry WHERE log_server_id = ?"
            result <- query conn sql (Only $ logServerId logServer) :: IO [Only Int]
            let start = only $ head $ result
            let end = start + 3000


            entries' <- getEntries logServer (start, end)
            case entries' of
                Just entries -> do
                    domains <- mapM extractDistinguishedName entries
                    let parameters = map (\(e, i, d) -> (logServerId logServer, i, d) :. e) $ zip3 entries [start..end] domains
                    _ <- executeMany conn "INSERT INTO log_entry (log_server_id, idx, domain, leaf_input, extra_data) VALUES (?, ?, ?, ?, ?)" parameters
                    return ()
                Nothing -> debugM "sync" "No entries" >> return ()

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
                    let sql = "SELECT * FROM sth WHERE treesize = ? AND timestamp = ? AND roothash = ? AND treeheadsignature = ?"
                    results <- query conn sql sth' :: IO [SignedTreeHead :. (Bool, Int)]
                    if (null results)
                        then execute conn "INSERT INTO sth (treesize, timestamp, roothash, treeheadsignature, log_server_id) VALUES (?, ?, ?, ?, ?)" (sth' :. Only (logServerId logServer)) >> return ()
                        else return ()
                Nothing   -> return ()


        processSth :: IO ()
        processSth = do
            debugM "processor" "Processing..."
            conn <- connect connectInfo
            logs <- logServers conn
            forM_ logs $ \log -> do
                knownGoodSth' <- query conn "SELECT * FROM sth WHERE verified = true AND log_server_id = ? ORDER BY timestamp LIMIT 1" (Only $ logServerId log) :: IO ([SignedTreeHead :. (Bool, Int)])

                if (null knownGoodSth')
                    then do errorM "processing" $ "Log " ++ show log ++ " has no known good STH. Set one such record verified."
                    else do
                        let knownGoodSth = first $ head knownGoodSth'
                        let sql = "SELECT * FROM sth WHERE verified = false AND log_server_id = ?"
                        results <- query conn sql (Only $ logServerId log) :: IO ([SignedTreeHead :. (Bool, Int)])
                        forM_ (map first results) $ \sth -> do
                            maybeConsistencyProof <- getSthConsistency log knownGoodSth sth
                            if (isGood $ checkConsistencyProof knownGoodSth sth <$> maybeConsistencyProof)
                                then do
                                    let updateSql = "UPDATE sth SET verified = true WHERE treesize = ? AND timestamp = ? AND roothash = ? AND treeheadsignature = ?"
                                    _ <- execute conn updateSql sth
                                    return ()
                                else errorM "processor" ("Unable to verify sth: " ++ show sth)

            close conn

        first :: (a :. b) -> a
        first (a :. _) = a

        isGood :: Maybe Bool -> Bool
        isGood (Just b) = b
        isGood Nothing  = False

        everyMinute a = forever $ a >> threadDelay (1*60*1000*1000)
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



right (Right a) = a

extractDistinguishedName :: LogEntry -> IO String
extractDistinguishedName logEntry = do
    E.catch (do
        let bs = logEntryLeafInput logEntry
        let merkleLeaf' = B.decodeOrFail $ BSL.pack $ BS.unpack $ bs
        case merkleLeaf' of
            Left (bs', bos, s) -> do
                errorM "ct-watch-sync" $ "Failed decoding logentry " ++ show logEntry ++ ". Details bs=" ++ show bs' ++ " bos=" ++ show bos ++ " s=" ++ show s
                return "FAILED"
            Right (_, _, merkleLeaf') -> do
                let rawCert = cert' $ timestampedEntry' merkleLeaf'
                debugM "" $ "raw cert: " ++ show (B64L.encode rawCert)
                let c = x509Cert $ right $ decodeCertificate rawCert
                let dn = certSubjectDN c
                str <- E.evaluate $ snd $ snd $ last $ getDistinguishedElements dn 
                return str
        ) (\e -> do
                    errorM "sync" $ "ffff" ++ show (e :: ASN1Error)
                    return "FAILED"
          )
