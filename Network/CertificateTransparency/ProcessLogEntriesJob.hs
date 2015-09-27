{-# LANGUAGE RankNTypes #-}

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
    updateDomainOfLogEntry conn logServer idx (collapseEither $ mapLeft renderFailureToDBString name)

data CertExtractionFailure = NoSANs | InvalidCert | ASN1Failure

renderFailureToDBString :: CertExtractionFailure -> String
renderFailureToDBString NoSANs = "noSANs-FAILED"
renderFailureToDBString InvalidCert = "decodeSignedCert-FAILED"
renderFailureToDBString ASN1Failure = "genericasn1-FAILED"

extractDistinguishedName'' :: SignedCertificate -> [String]
extractDistinguishedName'' c' = commonName ++ sans
    where
        c = getCertificate c'
        subjectDn = certSubjectDN c
        sans = [x | AltNameDNS x <- concat . map (\(ExtSubjectAltName e) -> e) . maybeToList . extensionGet . certExtensions $ c :: [AltName]]
        commonName = concat . map (maybeToList . asn1CharacterToString) . filter canDecode . map snd . getDistinguishedElements $ subjectDn
        canDecode (ASN1CharacterString e _) = e `elem` [IA5, UTF8, Printable, T61]


extractDistinguishedName' :: LogEntryDb -> Either CertExtractionFailure String
extractDistinguishedName' logEntry = domain
        where
            rawCert = logEntryDbCert logEntry
            sd = decodeSignedCertificate rawCert
            domain = case sd of
                Left _ -> Left InvalidCert
                Right crt -> if (null domains)
                        then Left NoSANs
                        else Right $ last domains
                    where
                        domains = extractDistinguishedName'' crt


extractDistinguishedName :: LogEntryDb -> IO (Either CertExtractionFailure String)
extractDistinguishedName logEntry = E.catch (return $ extractDistinguishedName' logEntry)
                                            (\e -> let _ = (e :: ASN1Error) in return $ Left ASN1Failure)

mapLeft :: (a -> b) -> Either a c -> Either b c
mapLeft f (Left x) = Left $ f x
mapLeft _ (Right x) = Right x

collapseEither :: forall c. Either c c -> c
collapseEither = either id id
