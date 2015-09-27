module Network.CertificateTransparency.LogServers (
    LogServer(),
    venafi,
    symantec,
    verify
) where

import Crypto.Hash.Algorithms
import qualified Crypto.PubKey.RSA.PKCS15 as PKCS15
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.Lazy as BSB64
import qualified Data.ByteString.Lazy.Char8 as C
import Data.X509

data LogServer = LogServer {
    name :: String,
    key :: PubKey
} deriving (Show)

venafi :: LogServer
venafi = LogServer { name = "ctlog.api.venafi.com", key = parseKey "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB"}

symantec :: LogServer
symantec = LogServer { name = "ct.ws.symantec.com", key = parseKey "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg=="}

parseKey :: String -> PubKey
parseKey = fst . right . fromASN1 . right . decodeASN1 DER . BSB64.decodeLenient . C.pack

right :: Either a b -> b
right (Right r) = r
right (Left _ ) = undefined

verify :: LogServer -> BS.ByteString -> BS.ByteString -> Bool
verify LogServer { key = PubKeyRSA k} m s = PKCS15.verify (Just SHA256) k m s
verify _ _ _ = undefined
