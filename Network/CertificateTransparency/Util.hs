module Network.CertificateTransparency.Util (
    logException
  , catchAny
) where

import Control.Concurrent.Async
import Control.Exception (SomeException)
import System.Log.Logger

logException :: SomeException -> IO ()
logException e = errorM "processor" ("Exception: " ++ show e)

catchAny :: IO a -> (SomeException -> IO a) -> IO a
catchAny action onE = tryAny action >>= either onE return

tryAny :: IO a -> IO (Either SomeException a)
tryAny action = withAsync action waitCatch
