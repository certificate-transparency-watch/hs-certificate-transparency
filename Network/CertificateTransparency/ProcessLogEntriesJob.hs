module Network.CertificateTransparency.ProcessLogEntriesJob (
    processLogEntries
) where

import qualified Control.Exception as E
import qualified Data.ByteString.Base64 as B64
import Control.Monad (forM_)
import Data.X509
import Network.CertificateTransparency.Db
import System.Log.Logger
import Data.ASN1.Error (ASN1Error)
import Network.CertificateTransparency.Types
import Data.Maybe (maybeToList)
import Database.PostgreSQL.Simple
import Data.ASN1.Types.String

processLogEntries :: ConnectInfo -> IO ()
processLogEntries connectInfo = do
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
                        str <- E.evaluate $ (concat . map (maybeToList . asn1CharacterToString) . filter canDecode . map snd . getDistinguishedElements $ dn) ++ san
                        return $ if (null str)
                            then "noSANs-FAILED"
                            else last str
        ) (\e -> do
                    errorM "sync" $ "ffff" ++ show (e :: ASN1Error)
                    return "genericasn1-FAILED"
          )

canDecode :: ASN1CharacterString -> Bool
canDecode (ASN1CharacterString e _) = e `elem` [IA5, UTF8, Printable, T61]
