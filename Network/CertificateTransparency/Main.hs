{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Base64 as B64

import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification

old = SignedTreeHead
    { treeSize = 1979426
    , timestamp = 1368891548960
    , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
    , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
    }

main = do
    newSth <- getSth

    case newSth of
        Just new -> do
            print $ show $ treeSize new
            consProof <- getSthConsistency old new
            case consProof of
                Just consProof' -> print $ show $ checkConsistencyProof old new consProof'
                _ -> error "q"
        _ -> error "qq"
