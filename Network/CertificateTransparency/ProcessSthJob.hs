module Network.CertificateTransparency.ProcessSthJob (
    processSth
) where

import Control.Monad (forM_)
import Database.PostgreSQL.Simple
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import System.Log.Logger

processSth :: ConnectInfo -> IO ()
processSth connectInfo = do
    debugM "processor" "Processing..."
    conn <- connect connectInfo
    logs <- logServers conn
    forM_ logs (processSthForLogServer conn)
    close conn

processSthForLogServer :: Connection -> LogServer -> IO ()
processSthForLogServer conn logServer = do
    knownGoodSth' <- lookupKnownGoodSth conn logServer
    case knownGoodSth' of
        Nothing -> errorM "processing" $ "Log " ++ show logServer ++ " has no known good STH. Set one such record verified."
        Just knownGoodSth -> do
            sths <- lookupUnverifiedSth conn logServer
            forM_ sths $ \sth -> do
                maybeConsistencyProof <- getSthConsistency logServer knownGoodSth sth
                if (isGood $ checkConsistencyProof knownGoodSth sth <$> maybeConsistencyProof)
                    then setSthToBeVerified conn sth
                    else errorM "processor" ("Unable to verify sth: " ++ show sth)

isGood :: Maybe Bool -> Bool
isGood (Just b) = b
isGood Nothing  = False
