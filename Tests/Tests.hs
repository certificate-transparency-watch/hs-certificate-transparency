{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BSC
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit

import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification

main :: IO ()
main = defaultMain tests

tests = [ testGroup "Consistency proof"
              [ testGroup "examples in RFC6962" consistencyProofsInRfc6962
              , testCase "first tree subtree of second" whenFirstTreeIsSubTreeOfSecond
              ]
        ]

consistencyProofsInRfc6962 = [
                               testCase "6 7" $ proof 6 7 @?= [6,7,2]
                             , testCase "4 7" $ proof 4 7 @?= [3]
                             , testCase "3 7" $ proof 3 7 @?= [10,11,4,3]
                             ]

whenFirstTreeIsSubTreeOfSecond = do
    let cert1 = (SHA256.hash . BSC.pack) "foo"
    let cert2 = (SHA256.hash . BSC.pack) "bar"
    let firstSTH = SignedTreeHead { treeSize = 1
                                  , timestamp = 42
                                  , rootHash = cert1
                                  , treeHeadSignature = (B64.encode . BSC.pack) "sig"
                                  }

    let secondSTH = SignedTreeHead { treeSize = 2
                                   , timestamp = 42+20
                                   , rootHash = merkleHashCombine cert1 cert2
                                   , treeHeadSignature = (B64.encode . BSC.pack) "sig2"
                                   }

    proof 1 2 @?= [3]

    let expectedProof = ConsistencyProof { proofCP = [cert2] }
    checkConsistencyProof firstSTH secondSTH expectedProof @?= True
