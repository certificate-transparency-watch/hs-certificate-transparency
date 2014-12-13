{-# LANGUAGE OverloadedStrings, TemplateHaskell #-}
module ConsistencyProof
    ( consistencyProofTestGroup
    ) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BSC
import Data.Maybe (fromJust)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit
import Test.Tasty.TH

import Network.CertificateTransparency.MerkleTree
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification

import GooglePilotLogServer

consistencyProofTestGroup = $(testGroupGenerator)

-- eww
case_end_to_end_test_against_google_pilot = case_testConsistencyAgainstGooglePilotLogServer

-- "The number of nodes in the resulting proof is bounded above by
--  ceil(log2(n)) + 1.)" -- http://tools.ietf.org/html/rfc6962#section-2.1.2
prop_nodes_in_proof_is_logarithmic a b =
    (a < b && a >= 1) ==>
    length (proof a b) <= limit
        where limit = 1 + (ceiling $ logBase 2 $ fromIntegral b)

test_consistency_proofs_in_RFC6962 = [
                               testCase "6 7" $ proof 6 7 @?= [6,7,2]
                             , testCase "4 7" $ proof 4 7 @?= [3]
                             , testCase "3 7" $ proof 3 7 @?= [10,11,4,3]
                             ]

case_when_first_tree_is_sub_tree_of_second = do
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
case_check_all_elements_from_first_tree_are_in_second = do
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
                                  , rootHash = fromJust $ merkleTreeRootHash tree1
                                  , treeHeadSignature = (B64.encode . BSC.pack) "sig"
                                  }

    let secondSTH = SignedTreeHead { treeSize = 4
                                   , timestamp = 42+20
                                   , rootHash = fromJust $ merkleTreeRootHash tree2
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

-- 
case_consistency_proof_from_google = do
    let prev = SignedTreeHead {
          treeSize = 1979426
        , timestamp = 1368891548960
        , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
        , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
        }

    let next = SignedTreeHead {
          treeSize  = 2741521
        , timestamp = 1380552724453
        , rootHash  = B64.decodeLenient "qRAV/VJicI8FZLfTJIU5kVFJQZ3aBizlSPRErTX61i4="
        , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAo2+OFDFjTdd61sDQEMXR14fJNTNin1wpJnTI9zSLnNYCIQCWEhHjQ7IIN8TuI6GPdvdJhDT/P56k+WxsoTPPLbgtsg=="
        }

    let proof = ConsistencyProof {
          proofCP = map B64.decodeLenient
            ["bblNpKGupBqDDigHMxwoXaBS05WnL2fj/qttPZGMzEI=","bO+5cy7VpbDGxdZLu5eh2rWNHOPxel8EzDHWoErDgS8=","3ePcgS9maoFBK52qhDyp5bpxOlOcfVMMGXSljHuWXAk=","YCnDylBZ8s3TyvzhgakvF2otmQdaM38qrNSyTWYfdAA=","dwhlYo0TyghF1Xq20renXFdKgj7XovvHfGGRgfW+iPE=","lmfI7Oy55S63pftxM8w1zXJb3h/Mtm8sPFkjtjtNChk=","FulAwmSb/SOe5/91dqeKayrd940GqPkn3hSi+4YitJE=","2NNhcfXetpWMlojc5PzJKvFWS25CMvKNvac41W6qoCA=","PMmfZMhO99mb1YUdjpWd6WMfUiJaGR/SQVLRnY7OTFQ=","8VQA+sR+AOIl1QOL021d/r3F/pFle5Cbh3SCeOikajY=","o+rk3kXIlwQY94iKb+RWmBD0hjGMCKYwtB/Htukoq/k=","r1cXdTQkFjUBOA4P99OpuLodYaIODm0xrWp4KgTN3Kg=","FkR0Luer+8Jjs7vgyCC+IRvcLF/Ms4cVCsHEDYLFJFE=","zPdQENIQJyo4slG1tPbWXJaRiijF3x8bt5cVt3DX6ug=","r0IRKDmmkHUOwluAiE7ZnQbCanCMVaHfXKGxFFlZV7k=","CStYNvBk3GSGsIqgbfzCI9cyJEu6WvtOX2XjHjNp99E=","TQECqBH0gDfmZJS3oY7wJd6y5fGpnT8JQ7lTCFvXe1U=","wSXPL0cesW52hzcTGS7kKR/sZCT64dhOe5l9wNqew2I=","eGwFccrO/9bveiiZEhcn6otGIH++Y7WamctkvuyoLF4=","qIqRIjnAB/zkrfX1aCaoZ0TAU6AgzYMfopCMUcRZcIg=","69MEfs3audDUKHQb+24jmupCgw8ASrtMgifycVb5k+M=","icxy5tOEVLPVPbunfkKGhqmpsPChciANfHEi520psYE="]
        }

    checkConsistencyProof prev next proof @?= True

case_consistency_proof_with_same_tree_sizes = do
    let prev = SignedTreeHead {
          treeSize = 1979426
        , timestamp = 1368891548960
        , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
        , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
        }

    let next = prev

    let proof = ConsistencyProof { proofCP = [] }

    checkConsistencyProof prev next proof @?= True


leaf :: Int -> ByteString -> MerkleTree
leaf i h = MerkleTree Empty i h Empty

merkleTreeHash :: MerkleTree -> ByteString
merkleTreeHash (MerkleTree _ _ h _) = h
merkleTreeHash Empty                = error "empty merkle tree has no hash"
