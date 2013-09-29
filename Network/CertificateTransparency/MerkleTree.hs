module Network.CertificateTransparency.MerkleTree
    ( buildMerkleTree
    , merkleTreeRootHash
    , merkleHashCombine -- visible for testing
    ) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (sortBy)
import Data.Ord (comparing)

data MerkleTree = Empty
                | MerkleTree MerkleTree Int Hash MerkleTree

merkleTreeRootHash :: MerkleTree -> Hash
merkleTreeRootHash (MerkleTree _ 1 h _) = h

type Hash = ByteString
buildMerkleTree :: [(Int, Hash)] -> MerkleTree
buildMerkleTree xs = foldl f Empty (reverse $ sortBy (comparing fst) xs)
    where
        f :: MerkleTree -> (Int, Hash) -> MerkleTree
        f Empty (i, h)                     = MerkleTree Empty i h Empty
        f prev@(MerkleTree _ j _ _ ) (i, h) = merkleCombine l r
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
    else MerkleTree l (i `div` 2) (merkleHashCombine h h2) r

merkleHashCombine :: Hash -> Hash -> Hash
merkleHashCombine x y = SHA256.hash $ BS.concat [BS.singleton 1, x, y]
