module Main where

import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit

import Verification

main :: IO ()
main = defaultMain tests

tests = [ testGroup "Consistency proof examples in RFC6962" consistencyProofsInRfc6962]

consistencyProofsInRfc6962 = [testCase "6 7" testFoo]

testFoo = proof 6 7 @?= [6,7,2]
testBar = proof 3 7 @?= [3,4,5]
