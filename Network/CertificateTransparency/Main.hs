{-# LANGUAGE OverloadedStrings, TypeOperators #-}

import qualified Data.ByteString.Base64 as B64

import Control.Applicative ((<$>), (<*>))
import Control.Concurrent (threadDelay, forkIO)
import Control.Concurrent.Async
import Control.Exception (SomeException)
import Control.Monad (forever, forM_, liftM)
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.FromRow
import Database.PostgreSQL.Simple.ToRow
import Database.PostgreSQL.Simple.ToField
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import System.Log.Logger

knownGoodSth :: SignedTreeHead
knownGoodSth = SignedTreeHead
    { treeSize = 1979426
    , timestamp = 1368891548960
    , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
    , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
    }

connectInfo :: ConnectInfo
connectInfo = defaultConnectInfo {
    connectDatabase = "ct-watch"
  , connectUser = "docker"
  , connectPassword = "docker"
  , connectHost = "172.17.42.1"
}

googlePilotLogServer :: Connection -> IO LogServer
googlePilotLogServer conn = do
    servers <- logServers conn
    return $ head $ filter (\ls -> logServerId ls == 1) servers

logServers :: Connection -> IO [LogServer]
logServers conn = withTransaction conn $ do
    let sql = "SELECT * FROM log_server"
    query_ conn sql :: IO [LogServer]



main :: IO ()
main = do
    setupLogging
    _ <- forkIO . everyMinute $ catchAny pollLogServersForSth logException
    _ <- forkIO . everyMinute $ catchAny processSth logException
    forever $ threadDelay (10*1000*1000)

    where
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
            googlePilotLog <- googlePilotLogServer conn
            let sql = "SELECT * FROM sth WHERE verified = false AND log_server_id = 1"
            results <- query_ conn sql :: IO ([SignedTreeHead :. (Bool, Int)])
            forM_ (map first results) $ \sth -> do
                maybeConsistencyProof <- getSthConsistency googlePilotLog knownGoodSth sth
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
