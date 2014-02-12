{-# LANGUAGE OverloadedStrings, TypeOperators #-}

import qualified Data.ByteString.Base64 as B64
import qualified Crypto.Hash.MD5 as MD5

import Control.Applicative ((<$>))
import Control.Concurrent (threadDelay, forkIO)
import Control.Concurrent.Async
import Control.Exception (SomeException)
import qualified Control.Exception as E
import Control.Monad (forever, forM_)
import Data.ASN1.Error (ASN1Error)
import qualified Data.Binary as B
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Data.ASN1.Types.String
import Data.Maybe
import Data.X509
import Database.PostgreSQL.Simple
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.StructParser()
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
    _ <- forkIO . everySeconds 10 $ catchAny syncLogEntries logException
    _ <- forkIO . everySeconds 10 $ catchAny processLogEntries logException
    forever $ threadDelay (10*1000*1000)

    where
        syncLogEntries :: IO ()
        syncLogEntries = do
            conn <- connect connectInfo
            servers <- logServers conn
            mapM_ (syncLogEntriesForLog conn) servers
            close conn


        syncLogEntriesForLog :: Connection -> LogServer -> IO ()
        syncLogEntriesForLog conn logServer = do
            debugM "sync" $ "Syncing " ++ show logServer
            start <- nextLogServerEntryForLogServer conn logServer
            let end = start + 2000

            entries' <- getEntries logServer (start, end)
            case entries' of
                Just entries -> do
                    let certs = concat . map (maybeToList . extractCert) $ entries

                    mapM_ (insertCert conn) certs

                    let parameters = map (\(cert, i) -> (logServerId logServer, i, Binary $ MD5.hashlazy cert)) $ zip certs [start..end]
                    _ <- executeMany conn "INSERT INTO log_entry (log_server_id, idx, cert_md5) VALUES (?, ?, ?)" parameters
                    return ()
                Nothing -> debugM "sync" "No entries" >> return ()

        processLogEntries :: IO ()
        processLogEntries = do
            conn <- connect connectInfo
            servers <- logServers conn
            forM_ servers $ \server -> do
                entries <- lookupUnprocessedLogEntries conn server
                mapM_ (\(Only i :. le) -> processLogEntry conn server i le) entries
            close conn

        processLogEntry :: Connection -> LogServer -> Int -> LogEntryDb -> IO ()
        processLogEntry conn logServer idx logEntry = do
            name <- extractDistinguishedName logEntry
            updateDomainOfLogEntry conn logServer idx name

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
                    sthExists' <- sthExists conn sth'
                    if (not sthExists')
                        then insertSth conn sth' logServer >> return ()
                        else return ()
                Nothing   -> return ()


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

extractDistinguishedName :: LogEntryDb -> IO String
extractDistinguishedName logEntry = do
    E.catch (do
                let rawCert = logEntryDbCert logEntry
                let sd = decodeSignedCertificate $ rawCert
                case sd of
                    Left s -> do
                        errorM "ct-watch-sync" $ "Failed decoding certificate: " ++ show (B64.encode rawCert) ++ " with error " ++ show s
                        return "decodeSignedCert-FAILED"
                    Right c' -> do
                        let c = getCertificate c'
                        let dn = certSubjectDN c
                        let san = [x | AltNameDNS x <- concat . map (\(ExtSubjectAltName e) -> e) . maybeToList . extensionGet . certExtensions $ c :: [AltName]]
                        str <- E.evaluate . last $ (concat . map (maybeToList . asn1CharacterToString) . filter canDecode . map snd . getDistinguishedElements $ dn) ++ san
                        return str
        ) (\e -> do
                    errorM "sync" $ "ffff" ++ show (e :: ASN1Error)
                    return "genericasn1-FAILED"
          )

extractCert :: LogEntry -> Maybe BSL.ByteString
extractCert logEntry = ans
    where
        bs = logEntryLeafInput logEntry
        merkleLeaf'' = B.decodeOrFail $ BSL.pack $ BS.unpack $ bs
        ans = case merkleLeaf'' of
            Left (bs', bos, s) -> error $ "LogEntry " ++ show (B64.encode bs) ++ " failed to parse. Bs=" ++ show bs' ++ " bos=" ++ show bos ++ " s=" ++ show s
            Right (_, _, merkleLeaf') -> Just $ cert' $ timestampedEntry' merkleLeaf'


canDecode :: ASN1CharacterString -> Bool
canDecode (ASN1CharacterString e _) = e `elem` [IA5, UTF8, Printable, T61]
