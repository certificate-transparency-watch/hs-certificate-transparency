{-# LANGUAGE OverloadedStrings, TypeOperators #-}

import qualified Data.ByteString.Base64 as B64

import qualified Control.Exception as E
import Control.Monad (forM_)
import Data.ASN1.Error (ASN1Error)
import Data.ASN1.Types.String
import Data.Either
import Data.Maybe
import Data.X509
import Database.PostgreSQL.Simple
import Prelude hiding (repeat)
import Network.CertificateTransparency.Db
import Network.CertificateTransparency.StructParser()
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Util
import System.Log.Logger

main :: IO ()
main = do
    setupLogging
    processLogEntries
    where
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
