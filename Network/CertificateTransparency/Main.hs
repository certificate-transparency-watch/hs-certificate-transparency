{-# LANGUAGE OverloadedStrings, TypeOperators #-}

import qualified Data.ByteString.Base64 as B64

import Control.Applicative ((<$>), (<*>))
import Control.Concurrent (threadDelay, forkIO)
import Control.Concurrent.Async
import Control.Exception (SomeException)
import qualified Control.Exception as E
import Control.Monad (forever, forM_, liftM)
import Data.ASN1.Types (ASN1Error)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import qualified Data.Binary as B
import Data.Binary.Get
import Data.Certificate.X509
import Data.Word
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.FromRow
import Database.PostgreSQL.Simple.ToRow
import Database.PostgreSQL.Simple.ToField
import Network.CertificateTransparency.LogServerApi
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

logServers :: Connection -> IO [LogServer]
logServers conn = withTransaction conn $ do
    let sql = "SELECT * FROM log_server"
    query_ conn sql :: IO [LogServer]

main :: IO ()
main = do
    setupLogging
    _ <- forkIO . everyMinute $ catchAny pollLogServersForSth logException
    _ <- forkIO . everyMinute $ catchAny processSth logException
    _ <- forkIO . everyMinute $ catchAny syncLogEntries logException
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
            let sql = "SELECT max(idx)+1 FROM log_entry WHERE log_server_id = ?"
            result <- query conn sql (Only $ logServerId logServer) :: IO [Only Int]
            let start = only $ head $ result
            let end = start + 500


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

instance ToRow LogEntry where
    toRow d = [ toField (B64.encode $ logEntryLeafInput d)
              , toField (B64.encode $ logEntryExtraData d)
              ]

instance B.Binary MerkleTreeLeaf where
    get = MerkleTreeLeaf <$> B.get <*> B.get <*> B.get
    put = undefined
             
instance B.Binary TimestampedEntry where
    get = do
        ts <- B.get
        et <- B.get

        a <- B.get :: B.Get Word8
        b <- B.get :: B.Get Word8
        c <- B.get :: B.Get Word8
        let length = 2^16 * (fromIntegral a) + 2^8 * (fromIntegral b) + (fromIntegral c)

        c <- getLazyByteString length

        return $ TimestampedEntry ts et (ASN1Cert $ x509Cert $ right $ decodeCertificate c)
    put = undefined

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
            Right (_, _, merkleLeaf) -> do
                let (ASN1Cert c) = cert $ timestampedEntry merkleLeaf
                let dn = certSubjectDN c
                str <- E.evaluate $ snd $ snd $ last $ getDistinguishedElements dn 
                return str
        ) (\e -> do
                    errorM "sync" $ "ffff" ++ show (e :: ASN1Error)
                    return "FAILED"
          )
