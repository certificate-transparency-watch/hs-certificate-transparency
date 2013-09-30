{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Base64 as B64

import Control.Applicative ((<$>))
import Control.Concurrent (threadDelay)
import Control.Monad
import Control.Monad.Loops (whileM_)
import Control.Monad.Maybe
import Control.Monad.Trans
import Data.Ord
import Data.IORef
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import System.Log.Handler.Syslog
import System.Log.Logger

knownGoodSth = SignedTreeHead
    { treeSize = 1979426
    , timestamp = 1368891548960
    , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
    , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
    }

main = do
    setupLogging

    sthRef <- newIORef (knownGoodSth, Just True)
    whileM_ (notFoundBadSth sthRef) $ do
        sth <- readIORef sthRef
        sthToStore <- updateAndCheck sth
        writeIORef sthRef sthToStore

        threadDelay (2*60*1000*1000) -- every 2 minutes

    badSth <- readIORef sthRef
    errorM "main" $ "The following STH failed its consistency check: " ++ show badSth

    where
        setupLogging :: IO ()
        setupLogging = do
            removeAllHandlers
            s <- openlog "ct-consistency-checker" [PID] DAEMON DEBUG
            updateGlobalLogger rootLoggerName (addHandler s)
            updateGlobalLogger rootLoggerName (setLevel DEBUG)
            infoM "main" "Logger started."

        notFoundBadSth :: IORef (SignedTreeHead, Maybe Bool) -> IO Bool
        notFoundBadSth ref = do
            sth <- readIORef ref
            return $ shouldContinue sth
                where
                    shouldContinue :: (SignedTreeHead, Maybe Bool) -> Bool
                    shouldContinue (sth, Just b)  = b
                    shouldContinue (sth, Nothing) = True

        updateAndCheck :: (SignedTreeHead, Maybe Bool) -> IO (SignedTreeHead, Maybe Bool)
        updateAndCheck (prevSth, prevB) = do
            nextSth' <- getSth
            case nextSth' of
                Just nextSth -> if (comparing treeSize prevSth nextSth == LT)
                                then do
                                    consProof <- getSthConsistency prevSth nextSth
                                    let r = (nextSth,
                                             checkConsistencyProof prevSth nextSth <$> consProof)
                                    debugM "main" $ "Iteration: " ++ show r
                                    return r
                                else return (prevSth, Nothing)
                Nothing      -> return (prevSth, prevB)
