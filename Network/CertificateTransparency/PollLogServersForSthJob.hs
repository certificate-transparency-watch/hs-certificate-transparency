module Network.CertificateTransparency.PollLogServersForSthJob (
    pollLogServersForSth
) where

import Database.PostgreSQL.Simple
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.Types
import System.Log.Logger

pollLogServersForSth :: ConnectInfo -> IO ()
pollLogServersForSth connectInfo = do
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
