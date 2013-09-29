module Network.CertificateTransparency.Verification
    ( checkConsistencyProof
    , proof -- visible for testing
    ) where

import Network.CertificateTransparency.MerkleTree
import Network.CertificateTransparency.Types

checkConsistencyProof :: SignedTreeHead -> SignedTreeHead -> ConsistencyProof -> Bool
checkConsistencyProof h1 h2 p = actual == expected
    where
        expected = rootHash h2
        actual = merkleTreeRootHash $ buildMerkleTree $ possibleLeftSubTree ++ zip proofNodePositions (proofCP p)
        proofNodePositions = proof (treeSize h1) (treeSize h2)
        possibleLeftSubTree =
            [(smallestPowerOfTwoLargerThanOrEqualTo (treeSize h2) `div` (treeSize h1), rootHash h1)
                    | isPowerOfTwo (treeSize h1)]


type NodeId = Int

proof :: Int -> Int -> [NodeId]
proof sizeA sizeB = subproof sizeA 1 (0, sizeB) True
    where
        subproof :: Int -> NodeId -> (Int,Int) -> Bool -> [NodeId]
        subproof m nodeId (n1,n2) b
            | b     && m == (n2-n1) = []
            | not b && m == (n2-n1) = [nodeId]
            | otherwise              =
                    let k = largestPowerOfTwoSmallerThan (n2-n1) in
                        if m <= k then
                            subproof m (nodeId*2) (0,k) b ++ [nodeId*2 + 1]
                        else
                            subproof (m-k) (nodeId*2+1) (n1+k, n2) False ++ [nodeId*2]

largestPowerOfTwoSmallerThan :: Integral a => a -> a
largestPowerOfTwoSmallerThan n = if largestSmallerThanOrEqualTo == n then n `div` 2 else largestSmallerThanOrEqualTo
    where largestSmallerThanOrEqualTo = round (2 ** fromIntegral (floor $ logBase 2 $ fromIntegral n :: Int))

smallestPowerOfTwoLargerThanOrEqualTo x = largestPowerOfTwoSmallerThan (2*x)

isPowerOfTwo :: Integral a => a -> Bool
isPowerOfTwo 1 = True
isPowerOfTwo x = 2*half == x && isPowerOfTwo half
    where half = x `div` 2
