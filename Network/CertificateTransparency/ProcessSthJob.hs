module Network.CertificateTransparency.ProcessSthJob (
    processSth
) where

import Control.Monad (forM_)
import Database.PostgreSQL.Simple
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.StructParser()
import Network.CertificateTransparency.Verification
import Prelude hiding (log)
import System.Log.Logger

processSth :: ConnectInfo -> IO ()
processSth connectInfo = do
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
