{-# LANGUAGE OverloadedStrings #-}
module Network.CertificateTransparency.LogServerApi
    ( getSth
    , getSthConsistency
    , getEntries
    ) where

import Data.Aeson
import Network.HTTP.Conduit
import Network.HTTP.Types()
import Network.HTTP.Types.Header()

import Network.CertificateTransparency.Parser()
import Network.CertificateTransparency.Types

getSth :: LogServer -> IO (Maybe SignedTreeHead)
getSth logServer = do
    req <- parseUrl $ "https://" ++ logServerPrefix logServer ++ "/ct/v1/get-sth"
    res <- withManager $ httpLbs req
    return . decode . responseBody $ res

getSthConsistency :: LogServer -> SignedTreeHead -> SignedTreeHead -> IO (Maybe ConsistencyProof)
getSthConsistency logServer h1 h2 = do
    req <- parseUrl $ "https://" ++ logServerPrefix logServer ++ "/ct/v1/get-sth-consistency?first=" ++ show (treeSize h1) ++ "&second=" ++ show (treeSize h2)
    res <- withManager $ httpLbs req
    return . decode . responseBody $ res

getEntries :: LogServer -> (Int, Int) -> IO (Maybe [LogEntry])
getEntries logServer (start, end) = do
    req <- parseUrl $ "https://" ++ logServerPrefix logServer ++ "/ct/v1/get-entries?start=" ++ show start ++ "&end=" ++ show end
    res <- withManager $ httpLbs req
    return $ logEntriesEntries <$> (decode . responseBody $ res)
