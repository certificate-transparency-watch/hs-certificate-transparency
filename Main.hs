{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import Control.Monad
import qualified Crypto.Hash.SHA256 as SHA256
import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.List (sortBy)
import Data.Ord (comparing)
import Data.Text

import Network.HTTP.Conduit
import Network.HTTP.Types
import Network.HTTP.Types.Header

rawOldSth = "{\
\    \"tree_size\": 1979426,\
\    \"timestamp\": 1368891548960,\
\    \"sha256_root_hash\": \"8UkrV2kjoLcZ5fP0xxVtpsSsWAnvcV8aPv39vh96J2o=\",\
\    \"tree_head_signature\":\"BAMASDBGAiEAxv3KBaV64XsRfqX4L8D1RGeIpEaPMXf+zdVXJ1hU7ZkCIQDmkXZhX/b52LRnq+9LKI/XYr1hgT6uYmiwRGn7DCx3+A==\"\
\}"

data SignedTreeHead = SignedTreeHead
    { treeSize :: Int
    , timestamp :: Int
    , rootHash :: ByteString
    , treeHeadSignature :: ByteString
    } deriving Show

instance FromJSON SignedTreeHead where
    parseJSON (Object v) = SignedTreeHead <$>
                            v .: "tree_size" <*>
                            v .: "timestamp" <*>
                            v .: "sha256_root_hash" <*>
                            v .: "tree_head_signature"
    parseJSON _          = mzero

data ConsistencyProof = ConsistencyProof
    { proofCP :: [ByteString]
    } deriving Show

instance FromJSON ConsistencyProof where
    parseJSON (Object v) = ConsistencyProof <$>
                            v .: "consistency"
    parseJSON _          = mzero

getSth = do
    initReq <- parseUrl "https://ct.googleapis.com/pilot/ct/v1/get-sth"

    let req' = initReq { secure = True
                       , method = "GET"
                       }
    res <- withManager $ httpLbs req'

    return $ responseBody res


data MerkleTreeNode = MerkleTreeNode

getSthConsistency :: SignedTreeHead -> SignedTreeHead -> IO (Maybe ConsistencyProof)
getSthConsistency h1 h2 = do
    initReq <- parseUrl $ "https://ct.googleapis.com/pilot/ct/v1/get-sth-consistency?first=" ++ show (treeSize h1) ++ "&second=" ++ show (treeSize h2)

    res <- withManager $ httpLbs initReq

    let consProof = decode $ responseBody res :: Maybe ConsistencyProof

    return $ decodeBase64ConsProof <$> consProof

decodeBase64ConsProof :: ConsistencyProof -> ConsistencyProof
decodeBase64ConsProof cp = ConsistencyProof { proofCP = Prelude.map B64.decodeLenient (proofCP cp) }

decodeBase64Sth :: SignedTreeHead -> SignedTreeHead
decodeBase64Sth sth = sth { rootHash = B64.decodeLenient (rootHash sth)}

checkConsistencyProof :: SignedTreeHead -> SignedTreeHead -> ConsistencyProof -> Bool
checkConsistencyProof h1 h2 p = actual == expected
    where
        expected = rootHash h2
        actual = buildMerkleTree $ foo ++ Prelude.zip proofNodePositions (proofCP p)
        proofNodePositions = proof (treeSize h1) (treeSize h2)
        foo = [(treeSize h1 `div` 2, rootHash h1) | isPowerOfTwo (treeSize h1)]

type Hash = ByteString
buildMerkleTree :: [(Int, Hash)] -> Hash
buildMerkleTree xs = go (Prelude.reverse $ sortBy (comparing fst) xs)
    where
        go :: [(Int, Hash)] -> Hash
        go [] = error "empty"
        go [(1, x)] = x
        go [(n, x)] = error $ "left with " ++ show (n, x)
        go ((x,xh):(y,yh):xs) = result where
            ((s, smaller), (l, larger)) = if x < y then ((x,xh), (y,yh)) else ((y,yh), (x,xh))
            result = if s + 1 /= l
                    then error $ "shit: " ++ show (s, l)
                else buildMerkleTree $ (x `div` 2, merkleCombine smaller larger) : xs

merkleCombine :: Hash -> Hash -> Hash
merkleCombine x y = SHA256.hash $ BS.concat [BS.singleton 1, x, y]

type NodeId = Int

proof :: Int -> Int -> [NodeId]
proof sizeA sizeB = subproof sizeA 1 (0, sizeB) True
    where
        subproof :: Int -> NodeId -> (Int,Int) -> Bool -> [NodeId]
        subproof m nodeId (n1,n2) b
            | b     && m == (n2-n1) = []
            | not b && m == (n2-n1) = [nodeId]
            | otherwise              =
                    let k = largestPowerOfTwoSmallerThan (n2-n1) in
                        if m <= k then
                            subproof m (nodeId*2) (0,k) b ++ [nodeId*2 + 1]
                        else
                            subproof (m-k) (nodeId*2+1) (n1+k, n2) False ++ [nodeId*2]

largestPowerOfTwoSmallerThan :: Integral a => a -> a
largestPowerOfTwoSmallerThan n = if largestSmallerThanOrEqualTo == n then n `div` 2 else largestSmallerThanOrEqualTo
    where largestSmallerThanOrEqualTo = round (2 ** fromIntegral (floor $ logBase 2 $ fromIntegral n :: Int))

isPowerOfTwo :: Integral a => a -> Bool
isPowerOfTwo x = 2 * largestPowerOfTwoSmallerThan x == x


main = do
    let oldSth = decode rawOldSth :: Maybe SignedTreeHead

    rawNewSth <- getSth
    let newSth' = decode rawNewSth :: Maybe SignedTreeHead
    let newSth = decodeBase64Sth <$> newSth'

    case oldSth of
        Just old ->
            case newSth of
                Just new -> do
                    print $ show $ treeSize new
                    consProof <- getSthConsistency old new
                    case consProof of
                        Just consProof' -> print $ show $ checkConsistencyProof old new consProof'
                        _ -> error "q"
                _ -> error "qq"
        _ -> error "qqrr"
