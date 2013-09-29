{-# LANGUAGE OverloadedStrings #-}
module Main where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BSC
import Test.Framework
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.HUnit
import Test.QuickCheck

import Network.CertificateTransparency.MerkleTree
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification

main :: IO ()
main = defaultMain tests

tests = [ testGroup "Consistency proof"
              [ testGroup "examples in RFC6962" consistencyProofsInRfc6962
              , testCase "first tree subtree of second" whenFirstTreeIsSubTreeOfSecond
              , testCase "check first tree" checkAllElementsFromFirstTreeAreInSecond
              , testProperty "number of nodes in proof is logarithmic" propNodesInProofIsLogarithmic
              ]
        ]

-- "The number of nodes in the resulting proof is bounded above by
--  ceil(log2(n)) + 1.)" -- http://tools.ietf.org/html/rfc6962#section-2.1.2
propNodesInProofIsLogarithmic a b =
    (a < b && a >= 1) ==>
    length (proof a b) <= limit
        where limit = 1 + (ceiling $ logBase 2 $ fromIntegral b)

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

-- In this test, the first test has 3 elements, [a,b,c].
-- Then, the second tree has 4 elements [a,b,x,d], such that the first tree
-- isn't a prefix! Element c is no longer in the tree. We should detect this.
-- 
-- Very ugly test. Will be refactorable once I have more tree generation code
checkAllElementsFromFirstTreeAreInSecond = do
    let tree1nodes = map (SHA256.hash . BSC.pack) ["a", "b", "c"]
    let tree2nodes = map (SHA256.hash . BSC.pack) ["a", "b", "x", "d"]

    let tree1 = let
              node_4 = leaf 4 $ tree1nodes !! 0
              node_5 = leaf 5 $ tree1nodes !! 1
              node_3 = leaf 3 $ tree1nodes !! 2
              node_2 = merkleCombine node_4 node_5
              node_1 = merkleCombine node_2 node_3
            in node_1

    let tree2 = let
               node_4 = leaf 4 $ tree2nodes !! 0
               node_5 = leaf 5 $ tree2nodes !! 1
               node_6 = leaf 6 $ tree2nodes !! 2
               node_7 = leaf 7 $ tree2nodes !! 3
               node_2 = merkleCombine node_4 node_5
               node_3 = merkleCombine node_6 node_7
               node_1 = merkleCombine node_2 node_3
            in node_1

    let firstSTH = SignedTreeHead { treeSize = 3
                                  , timestamp = 42
                                  , rootHash = merkleTreeRootHash tree1
                                  , treeHeadSignature = (B64.encode . BSC.pack) "sig"
                                  }

    let secondSTH = SignedTreeHead { treeSize = 4
                                   , timestamp = 42+20
                                   , rootHash = merkleTreeRootHash tree2
                                   , treeHeadSignature = (B64.encode . BSC.pack) "sig2"
                                   }

    proof 3 4 @?= [6,7,2]
    let expectedProof = ConsistencyProof { proofCP =
                            [ merkleTreeHash $ leaf 6 $ tree2nodes !! 2
                            , merkleTreeHash $ leaf 7 $ tree2nodes !! 3
                            , merkleTreeHash $ merkleCombine (leaf 4 $ tree2nodes !! 0) (leaf 5 $ tree2nodes !! 1 )
                            ]
                         }

    checkConsistencyProof firstSTH secondSTH expectedProof @?= False

leaf :: Int -> ByteString -> MerkleTree
leaf i h = MerkleTree Empty i h Empty
