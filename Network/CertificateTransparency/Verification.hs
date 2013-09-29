module Network.CertificateTransparency.Verification
    ( checkConsistencyProof
    , proof -- visible for testing
    , merkleCombine -- visible for testing
    ) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.List (sortBy)
import Data.Ord (comparing)

import Network.CertificateTransparency.Types

checkConsistencyProof :: SignedTreeHead -> SignedTreeHead -> ConsistencyProof -> Bool
checkConsistencyProof h1 h2 p = actual == expected
    where
        expected = rootHash h2
        actual = buildMerkleTree $ possibleLeftSubTree ++ zip proofNodePositions (proofCP p)
        proofNodePositions = proof (treeSize h1) (treeSize h2)
        possibleLeftSubTree =
            [(smallestPowerOfTwoLargerThanOrEqualTo (treeSize h2) `div` (treeSize h1), rootHash h1)
                    | isPowerOfTwo (treeSize h1)]

type Hash = ByteString
buildMerkleTree :: [(Int, Hash)] -> Hash
buildMerkleTree xs = case buildMT (reverse $ sortBy (comparing fst) xs) of
    Empty -> error "foo"
    MerkleTree _ _ h _ -> h

data MerkleTree = Empty
                | MerkleTree MerkleTree Int Hash MerkleTree

buildMT :: [(Int, Hash)] -> MerkleTree
buildMT xs = foldl f Empty xs
    where
        f :: MerkleTree -> (Int, Hash) -> MerkleTree
        f Empty (i, h)                     = MerkleTree Empty i h Empty
        f prev@(MerkleTree _ j _ _ ) (i, h) = merkleCombine' l r
              where new = MerkleTree Empty i h Empty
                    (l, r) = if i + 1 == j -- i is left child
                               then (new, prev)
                             else if j+1 == i -- j is left child
                                then (prev, new)
                             else
                                error "nope"


merkleCombine :: MerkleTree -> MerkleTree -> MerkleTree
merkleCombine _ Empty = error "nope"
merkleCombine Empty _ = error "nope"
merkleCombine l@(MerkleTree _ i h _) r@(MerkleTree _ j h2 _) = if i+1 /= j
    then error "foo"
    else MerkleTree l (i `div` 2) (merkleCombine h h2) r

merkleHashCombine :: Hash -> Hash -> Hash
merkleHashCombine x y = SHA256.hash $ BS.concat [BS.singleton 1, x, y]

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
