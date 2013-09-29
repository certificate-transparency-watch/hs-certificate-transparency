{-# LANGUAGE OverloadedStrings #-}
module Network.CertificateTransparency.LogServerApi
    ( getSth
    , getSthConsistency
    ) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad
import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import qualified Data.Text as T
import Network.HTTP.Conduit
import Network.HTTP.Types
import Network.HTTP.Types.Header
import System.Log.Logger (debugM)

import Network.CertificateTransparency.Types

instance FromJSON SignedTreeHead where
    parseJSON (Object v) = SignedTreeHead <$>
                            v .: "tree_size" <*>
                            v .: "timestamp" <*>
                            v .: "sha256_root_hash" <*>
                            v .: "tree_head_signature"
    parseJSON _          = mzero


instance FromJSON ConsistencyProof where
    parseJSON (Object v) = ConsistencyProof <$>
                            v .: "consistency"
    parseJSON _          = mzero

getSth :: IO (Maybe SignedTreeHead)
getSth = do
    rawNewSth <- getSth'
    let newSth' = decode rawNewSth :: Maybe SignedTreeHead
    return $ decodeBase64Sth <$> newSth'


getSth' :: IO BSL.ByteString
getSth' = do
    initReq <- parseUrl "https://ct.googleapis.com/pilot/ct/v1/get-sth"

    let req' = initReq { secure = True
                       , method = "GET"
                       }
    res <- withManager $ httpLbs req'

    let r =  responseBody res

    debugM "get-sth" $ BSLC.unpack r

    return r


getSthConsistency :: SignedTreeHead -> SignedTreeHead -> IO (Maybe ConsistencyProof)
getSthConsistency h1 h2 = do
    let url = "https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=" ++ show (treeSize h1) ++ "&second=" ++ show (treeSize h2)
    initReq <- parseUrl url

    res <- withManager $ httpLbs initReq

    let r = responseBody res

    debugM url $ BSLC.unpack r

    let consProof = decode r :: Maybe ConsistencyProof

    return $ decodeBase64ConsProof <$> consProof

decodeBase64ConsProof :: ConsistencyProof -> ConsistencyProof
decodeBase64ConsProof cp = ConsistencyProof { proofCP = map B64.decodeLenient (proofCP cp) }

decodeBase64Sth :: SignedTreeHead -> SignedTreeHead
decodeBase64Sth sth = sth { rootHash = B64.decodeLenient (rootHash sth)}
