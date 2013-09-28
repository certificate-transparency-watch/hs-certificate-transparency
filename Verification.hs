module Verification
    ( checkConsistencyProof
    , proof -- visible for testing
    ) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.List (sortBy)
import Data.Ord (comparing)

import Types

checkConsistencyProof :: SignedTreeHead -> SignedTreeHead -> ConsistencyProof -> Bool
checkConsistencyProof h1 h2 p = actual == expected
    where
        expected = rootHash h2
        actual = buildMerkleTree $ foo ++ zip proofNodePositions (proofCP p)
        proofNodePositions = proof (treeSize h1) (treeSize h2)
        foo = [(treeSize h1 `div` 2, rootHash h1) | isPowerOfTwo (treeSize h1)]

type Hash = ByteString
buildMerkleTree :: [(Int, Hash)] -> Hash
buildMerkleTree xs = go (reverse $ sortBy (comparing fst) xs)
    where
        go :: [(Int, Hash)] -> Hash
        go [] = error "empty"
        go [(1, x)] = x
        go [(n, x)] = error $ "left with " ++ show (n, x)
        go ((x,xh):(y,yh):xs) = result where
            ((s, smaller), (l, larger)) = if x < y then ((x,xh), (y,yh)) else ((y,yh), (x,xh))
            result = if s + 1 /= l
                    then error $ "not good: " ++ show (s, l)
                else buildMerkleTree $ (x `div` 2, merkleCombine smaller larger) : xs

merkleCombine :: Hash -> Hash -> Hash
merkleCombine x y = SHA256.hash $ BS.concat [BS.singleton 1, x, y]

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

isPowerOfTwo :: Integral a => a -> Bool
isPowerOfTwo x = 2 * largestPowerOfTwoSmallerThan x == x
