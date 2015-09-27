module Network.CertificateTransparency.ProcessLogEntriesJob (
    processLogEntries
) where

import qualified Control.Exception as E
import Control.Monad (forM_)
import Data.X509
import Network.CertificateTransparency.Db
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

data CertExtractionFailure = NoSANs | InvalidCert

extractDistinguishedName'' :: SignedCertificate -> [String]
extractDistinguishedName'' c' = commonName ++ sans
    where
        c = getCertificate c'
        subjectDn = certSubjectDN c
        sans = [x | AltNameDNS x <- concat . map (\(ExtSubjectAltName e) -> e) . maybeToList . extensionGet . certExtensions $ c :: [AltName]]
        commonName = concat . map (maybeToList . asn1CharacterToString) . filter canDecode . map snd . getDistinguishedElements $ subjectDn
        canDecode (ASN1CharacterString e _) = e `elem` [IA5, UTF8, Printable, T61]


extractDistinguishedName' :: LogEntryDb -> Either CertExtractionFailure String
extractDistinguishedName' logEntry = res
        where
            rawCert = logEntryDbCert logEntry
            sd = decodeSignedCertificate $ rawCert
            res = case sd of
                Left _ -> Left InvalidCert
                Right c' -> if (null res'')
                        then Left NoSANs
                        else Right $ last res''
                    where
                        res'' = extractDistinguishedName'' c'


extractDistinguishedName :: LogEntryDb -> IO String
extractDistinguishedName logEntry = do
    E.catch (return $ case extractDistinguishedName' logEntry of
                        Left NoSANs -> "noSANs-FAILED"
                        Left InvalidCert -> "decodeSignedCert-FAILED"
                        Right s -> s
            )
            (\e -> let _ = (e :: ASN1Error) in return "genericasn1-FAILED")
