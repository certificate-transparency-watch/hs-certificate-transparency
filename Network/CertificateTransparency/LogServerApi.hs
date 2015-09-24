{-# LANGUAGE OverloadedStrings #-}
module Network.CertificateTransparency.LogServerApi
    ( getSth
    , getSthConsistency
    , getEntries
    ) where

import Data.Aeson
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Network.HTTP.Conduit
import Network.HTTP.Types()
import Network.HTTP.Types.Header()
import System.Log.Logger (debugM)

import Network.CertificateTransparency.Parser()
import Network.CertificateTransparency.Types

getSth :: LogServer -> IO (Maybe SignedTreeHead)
getSth logServer = do
    initReq <- parseUrl $ "https://" ++ logServerPrefix logServer ++ "/ct/v1/get-sth"

    let req' = initReq { secure = True
                       , method = "GET"
                       }
    res <- withManager $ httpLbs req'

    let rawNewSth =  responseBody res

    debugM "get-sth" $ BSLC.unpack rawNewSth

    return $ decode rawNewSth


getSthConsistency :: LogServer -> SignedTreeHead -> SignedTreeHead -> IO (Maybe ConsistencyProof)
getSthConsistency logServer h1 h2 = do
    let url = "https://" ++ logServerPrefix logServer ++ "/ct/v1/get-sth-consistency?first=" ++ show (treeSize h1) ++ "&second=" ++ show (treeSize h2)
    initReq <- parseUrl url

    res <- withManager $ httpLbs initReq

    let r = responseBody res

    debugM url $ BSLC.unpack r

    return $ decode r

getEntries :: LogServer -> (Int, Int) -> IO (Maybe [LogEntry])
getEntries logServer (start, end) = do
    let url = "https://" ++ logServerPrefix logServer ++ "/ct/v1/get-entries?start=" ++ show start ++ "&end=" ++ show end

    initReq <- parseUrl url

    res <- withManager $ httpLbs initReq

    let r = responseBody res

    return $ logEntriesEntries <$> decode r
