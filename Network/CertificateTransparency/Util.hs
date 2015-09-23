module Network.CertificateTransparency.Util where 

import Database.PostgreSQL.Simple
import System.Log.Logger

connectInfo :: ConnectInfo
connectInfo = defaultConnectInfo {
    connectDatabase = "ct-watch"
  , connectUser = "docker"
  , connectPassword = "docker"
  , connectHost = "172.17.42.1"
}

setupLogging :: IO ()
setupLogging = do
    updateGlobalLogger rootLoggerName (setLevel DEBUG)
    infoM "main" "Logger started."
