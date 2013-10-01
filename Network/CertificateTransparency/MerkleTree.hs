{-# LANGUAGE Safe #-}
module Network.CertificateTransparency.MerkleTree
    ( buildMerkleTree
    , merkleTreeRootHash
    , merkleCombine -- visible for testing
    , merkleHashCombine -- visible for testing
    , MerkleTree(..)
    ) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.List (sortBy)
import Data.Ord (comparing)

data MerkleTree = Empty
                | MerkleTree MerkleTree Int Hash MerkleTree
                deriving (Show)

merkleTreeRootHash :: MerkleTree -> Maybe Hash
merkleTreeRootHash (MerkleTree _ 1 h _) = Just h
merkleTreeRootHash _                    = Nothing

type Hash = ByteString
buildMerkleTree :: [(Int, Hash)] -> MerkleTree
buildMerkleTree xs = foldl f Empty (reverse $ sortBy (comparing fst) xs)
    where
        f :: MerkleTree -> (Int, Hash) -> MerkleTree
        f Empty (i, h)                     = MerkleTree Empty i h Empty
        f prev@(MerkleTree _ j _ _ ) (i, h) = merkleCombine l r
              where new = MerkleTree Empty i h Empty
                    (l, r)
                        | i + 1 == j = (new, prev) -- i is left childthen
                        | j + 1 == i = (prev, new) -- j is left child
                        | otherwise  = error "nope"

merkleCombine :: MerkleTree -> MerkleTree -> MerkleTree
merkleCombine _ Empty = error "nope"
merkleCombine Empty _ = error "nope"
merkleCombine l@(MerkleTree _ i h _) r@(MerkleTree _ j h2 _) = if i+1 /= j
    then error "foo"
    else MerkleTree l (i `div` 2) (merkleHashCombine h h2) r

merkleHashCombine :: Hash -> Hash -> Hash
merkleHashCombine x y = SHA256.hash $ BS.concat [BS.singleton 1, x, y]
