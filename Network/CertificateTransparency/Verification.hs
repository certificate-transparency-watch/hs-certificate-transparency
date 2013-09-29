module Network.CertificateTransparency.Verification
    ( checkConsistencyProof
    , proof -- visible for testing
    ) where

import Network.CertificateTransparency.MerkleTree
import Network.CertificateTransparency.Types

import Data.ByteString (ByteString)
import Data.List (sortBy)
import Data.Ord (comparing)

checkConsistencyProof :: SignedTreeHead -> SignedTreeHead -> ConsistencyProof -> Bool
checkConsistencyProof h1 h2 p = firstTreeIsValid && secondTreeIsValid
    where
        -- I've yet to convince myself this is check sufficient, or even non-broken.
        -- I suspect it's non-broken at least, because it passes for consistency proofs on
        -- Google's 22mill+ log server.
        firstTreeIsValid  = rootHash h1 == build proofNodePositions
        secondTreeIsValid = rootHash h2 == (merkleTreeRootHash . buildMerkleTree) proofNodePositions
        proofNodePositions = zip (proof (treeSize h1) (treeSize h2)) (proofCP p)
                            ++ possibleLeftSubTree
            where
                -- If h1 is a subtree of h2, we need h1's hash, but it won't be in the consistency
                -- proof.
                possibleLeftSubTree =
                    [(smallestPowerOfTwoLargerThanOrEqualTo (treeSize h2) `div` treeSize h1, rootHash h1)
                            | isPowerOfTwo (treeSize h1)]

        build :: [(Int, ByteString)] -> ByteString
        build xs = (foldr1 f . map snd . sortBy (comparing fst) . filter (\(i, _) -> even i)) xs
            where
                f :: ByteString -> ByteString -> ByteString
                f h acc = merkleHashCombine h acc

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
