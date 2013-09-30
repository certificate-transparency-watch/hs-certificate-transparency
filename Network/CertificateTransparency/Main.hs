{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Base64 as B64

import Control.Applicative ((<$>))
import Control.Concurrent (threadDelay)
import Control.Monad
import Control.Monad.Loops (whileM_)
import Control.Monad.Maybe
import Control.Monad.Trans
import Data.IORef
import Network.CertificateTransparency.LogServerApi
import Network.CertificateTransparency.Types
import Network.CertificateTransparency.Verification
import System.Log.Handler.Syslog
import System.Log.Logger

old = SignedTreeHead
    { treeSize = 1979426
    , timestamp = 1368891548960
    , rootHash = B64.decodeLenient "8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o="
    , treeHeadSignature = B64.decodeLenient "BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A=="
    }

main = do
    setupLogging
    ref <- newIORef $ Just (old, Just True)

    whileM_ (notFoundBadSth ref) $ do
        sth <- readIORef ref
        case sth of
            Just (sth', _) -> do
                next <- oneIteration sth'
                debugM "main" $ "Iteration complete: " ++ show next
                writeIORef ref next
        threadDelay (2*60*1000*1000) -- every 2 minutes

    badSth <- readIORef ref
    errorM "main" $ "The following STH failed its consistency check: " ++ show badSth

setupLogging :: IO ()
setupLogging = do
    removeAllHandlers
    s <- openlog "ct-consistency-checker" [PID] DAEMON DEBUG
    updateGlobalLogger rootLoggerName (addHandler s)
    updateGlobalLogger rootLoggerName (setLevel DEBUG)
    infoM "main" "Logger started."

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
oneIteration old = runMaybeT $ MaybeT getSth >>= lift . (checkConsistency old)
    where
        checkConsistency :: SignedTreeHead -> SignedTreeHead -> IO (SignedTreeHead, Maybe Bool)
        checkConsistency old new = do
            consProof <- getSthConsistency old new
            return (new, checkConsistencyProof old new <$> consProof)

