module Main where

import Test.Framework
import Test.Framework.Providers.HUnit
import Test.HUnit

import Network.CertificateTransparency.Verification

main :: IO ()
main = defaultMain tests

tests = [ testGroup "Consistency proof examples in RFC6962" consistencyProofsInRfc6962]

consistencyProofsInRfc6962 = [
                               testCase "6 7" $ proof 6 7 @?= [6,7,2]
                             , testCase "4 7" $ proof 4 7 @?= [3]
                             , testCase "3 7" $ proof 3 7 @?= [10,11,4,3]
                             ]
