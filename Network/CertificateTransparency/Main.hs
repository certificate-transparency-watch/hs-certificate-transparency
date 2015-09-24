import Control.Concurrent (threadDelay, forkIO)
import Control.Monad (forever)
import Database.PostgreSQL.Simple
import Network.CertificateTransparency.PollLogServersForSthJob
import Network.CertificateTransparency.ProcessLogEntriesJob
import Network.CertificateTransparency.ProcessSthJob
import Network.CertificateTransparency.SyncLogEntriesJob
import Network.CertificateTransparency.Util
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
    _ <- forkIO . everySeconds 157 $ catchAny (processSth connectInfo) logException
    _ <- forkIO . everySeconds 31 $ catchAny (syncLogEntries connectInfo) logException
    _ <- forkIO . everySeconds 17 $ catchAny (processLogEntries connectInfo) logException
    forever $ threadDelay (10*1000*1000)

    where
        everySeconds n a = forever $ a >> threadDelay (n*1000*1000)

        setupLogging :: IO ()
        setupLogging = do
            updateGlobalLogger rootLoggerName (setLevel DEBUG)
            infoM "main" "Logger started."
