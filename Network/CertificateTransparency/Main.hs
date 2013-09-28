{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Base64 as B64

import Control.Concurrent (threadDelay)
import Control.Monad
import Control.Monad.Loops (whileM_)
import Data.IORef
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
    ref <- newIORef $ Just (old, Just True)

    whileM_ (notFoundBadSth ref) $ do
        sth <- readIORef ref
        case sth of
            Just (sth', _) -> do
                next <- oneIteration sth'
                print next
                writeIORef ref next
        threadDelay (2*60*1000*1000) -- every 2 minutes

    badSth <- readIORef ref
    print badSth

notFoundBadSth :: IORef (Maybe (SignedTreeHead, Maybe Bool)) -> IO Bool
notFoundBadSth ref = do
    sth <- readIORef ref
    return $ shouldContinue sth

shouldContinue :: Maybe (SignedTreeHead, Maybe Bool) -> Bool
shouldContinue (Just (sth, Just True))  = True
shouldContinue (Just (sth, Just False)) = False
shouldContinue (Just (sth, Nothing))    = True
shouldContinue Nothing                = True


oneIteration :: SignedTreeHead -> IO (Maybe (SignedTreeHead, Maybe Bool))
oneIteration sth = do
    newSth <- getSth

    case newSth of
        Just new -> do
            consProof <- getSthConsistency old new
            case consProof of
                Just consProof' -> do
                    if checkConsistencyProof old new consProof'
                        then return $ Just (new, Just True)
                        else return $ Just (new, Just False)
                _ -> return $ Just (new, Nothing)
        _ -> return Nothing
