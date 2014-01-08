{-# LANGUAGE OverloadedStrings #-}

module GooglePilotLogServer
    ( case_testConsistencyAgainstGooglePilotLogServer
    ) where

import Control.Applicative ((<$>))
import Data.Aeson (decode)
import qualified Data.ByteString.Lazy.Char8 as BSLC8
import Data.List (groupBy)
import Data.Maybe (catMaybes)
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Parser
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import Test.Tasty
import Test.Tasty.HUnit

googlePilotLog = LogServer
    { logServerPrefix = "ct.googleapis.com/pilot"
    }

case_testConsistencyAgainstGooglePilotLogServer :: Assertion
case_testConsistencyAgainstGooglePilotLogServer = do
    rHeads <- rawHeads
    let uniqueHeads = uniqueSths $ map parse rHeads
    sthsWithNoValidProofs <- sthsWithNoValidProof (head uniqueHeads) (tail uniqueHeads)
    (null sthsWithNoValidProofs) @? (show sthsWithNoValidProofs)

sthsWithNoValidProof :: SignedTreeHead -> [SignedTreeHead] -> IO [SignedTreeHead]
sthsWithNoValidProof x xs = do
    results <- mapM (check x) xs
    return . map fst . filter (bad . snd) $ zip xs results

    where
        bad :: Maybe Bool -> Bool
        bad (Just p) = not p
        bad Nothing  = True

        check :: SignedTreeHead -> SignedTreeHead -> IO (Maybe Bool)
        check s1 s2 = do
            proof <- getSthConsistency googlePilotLog s1 s2
            return $ checkConsistencyProof s1 s2 <$> proof

uniqueSths :: [Maybe SignedTreeHead] -> [SignedTreeHead]
uniqueSths = map head . groupBy (\x y -> treeSize x == treeSize y) . catMaybes

parse :: String -> Maybe SignedTreeHead
parse s = decode (BSLC8.pack s) :: Maybe SignedTreeHead

rawHeads :: IO [String]
rawHeads = do
    input <- readFile "Tests/google-pilot-log-sth.txt"
    return $ lines input
