{-# LANGUAGE OverloadedStrings #-}
module Network.CertificateTransparency.LogServerApi
    ( getSth
    , getSthConsistency
    ) where

import Data.Aeson
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Network.HTTP.Conduit
import Network.HTTP.Types()
import Network.HTTP.Types.Header()
import System.Log.Logger (debugM)

import Network.CertificateTransparency.Parser()
import Network.CertificateTransparency.Types

getSth :: IO (Maybe SignedTreeHead)
getSth = do
    initReq <- parseUrl "https://ct.googleapis.com/pilot/ct/v1/get-sth"

    let req' = initReq { secure = True
                       , method = "GET"
                       }
    res <- withManager $ httpLbs req'

    let rawNewSth =  responseBody res

    debugM "get-sth" $ BSLC.unpack rawNewSth

    return (decode rawNewSth :: Maybe SignedTreeHead)


getSthConsistency :: SignedTreeHead -> SignedTreeHead -> IO (Maybe ConsistencyProof)
getSthConsistency h1 h2 = do
    let url = "https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=" ++ show (treeSize h1) ++ "&second=" ++ show (treeSize h2)
    initReq <- parseUrl url

    res <- withManager $ httpLbs initReq

    let r = responseBody res

    debugM url $ BSLC.unpack r

    return (decode r :: Maybe ConsistencyProof)
