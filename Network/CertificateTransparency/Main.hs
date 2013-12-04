{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Base64 as B64

import Control.Applicative ((<$>), (<*>))
import Control.Concurrent (threadDelay, forkIO, yield)
import Control.Monad (forever, forM_, liftM)
import Control.Monad.Loops (whileM_)
import Data.Ord
import Data.IORef
import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.FromRow
import Database.PostgreSQL.Simple.ToRow
import Database.PostgreSQL.Simple.ToField
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import System.Log.Handler.Syslog
import System.Log.Logger

knownGoodSth :: SignedTreeHead
knownGoodSth = SignedTreeHead
    { treeSize = 1979426
    , timestamp = 1368891548960
    , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
    , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
    }


connectInfo = defaultConnectInfo {
    connectDatabase = "ct-watch"
  , connectUser = "tom"
  , connectPassword = "password"
}

main :: IO ()
main = do
    setupLogging
    forkIO . everyMinute $ pollLogServerForSth
    forkIO . everyMinute $ processSth
    forever yield

    where
        pollLogServerForSth :: IO ()
        pollLogServerForSth = do
            debugM "poller" "Polling..."
            conn <- connect connectInfo
            sth <- getSth
            case sth of
                Just sth' -> withTransaction conn $ do
                    let sql = "SELECT treesize, timestamp, roothash, treeheadsignature FROM sth WHERE treesize = ? AND timestamp = ? AND roothash = ? AND treeheadsignature = ?"
                    results <- query conn sql sth' :: IO [SignedTreeHead]
                    if (null results)
                        then execute conn "INSERT INTO sth (treesize, timestamp, roothash, treeheadsignature) VALUES (?, ?, ?, ?)" sth' >> return ()
                        else return ()
                Nothing   -> return ()

            close conn

        processSth :: IO ()
        processSth = do
            debugM "processor" "Processing..."
            conn <- connect connectInfo
            let sql = "SELECT treesize,timestamp,roothash,treeheadsignature FROM sth WHERE verified = false"
            results <- query_ conn sql :: IO [SignedTreeHead]
            forM_ results $ \sth -> do
                maybeConsistencyProof <- getSthConsistency knownGoodSth sth
                if (isGood $ checkConsistencyProof knownGoodSth sth <$> maybeConsistencyProof)
                    then do
                        let updateSql = "UPDATE sth SET verified = true WHERE treesize = ? AND timestamp = ? AND roothash = ? AND treeheadsignature = ?"
                        execute conn updateSql sth
                        return ()
                    else errorM "processor" ("Unable to verify sth: " ++ show sth)

            close conn

        isGood :: Maybe Bool -> Bool
        isGood (Just b) = b
        isGood Nothing  = False

        everyMinute a = forever $ a >> threadDelay (1*60*1000*1000)

        setupLogging :: IO ()
        setupLogging = do
            removeAllHandlers
            s <- openlog "ct-consistency-checker" [PID] DAEMON DEBUG
            updateGlobalLogger rootLoggerName (addHandler s)
            updateGlobalLogger rootLoggerName (setLevel DEBUG)
            infoM "main" "Logger started."


instance ToRow SignedTreeHead where
    toRow d = [ toField (treeSize d)
              , toField (timestamp d)
              , toField (B64.encode $ rootHash d)
              , toField (B64.encode $ treeHeadSignature d)
              ]

instance FromRow SignedTreeHead where
    fromRow = SignedTreeHead <$> field <*> field <*> (liftM B64.decodeLenient field) <*> (liftM B64.decodeLenient field)

