module Main where

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit

import ConsistencyProof

main :: IO ()
main = defaultMain $ testGroup "Tests" [consistencyProofTestGroup]
