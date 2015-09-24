{-# LANGUAGE TypeOperators #-}

import Control.Concurrent (threadDelay, forkIO)
import Control.Monad (forever, forM_)
import Database.PostgreSQL.Simple
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.PollLogServersForSthJob
import Network.CertificateTransparency.ProcessLogEntriesJob
import Network.CertificateTransparency.StructParser()
import Network.CertificateTransparency.SyncLogEntriesJob
import Network.CertificateTransparency.Util
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
    _ <- forkIO . everySeconds 59 $ catchAny (pollLogServersForSth connectInfo) logException
    _ <- forkIO . everySeconds 157 $ catchAny processSth logException
    _ <- forkIO . everySeconds 31 $ catchAny (syncLogEntries connectInfo) logException
    _ <- forkIO . everySeconds 17 $ catchAny (processLogEntries connectInfo) logException
    forever $ threadDelay (10*1000*1000)

    where

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
