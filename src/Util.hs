module P2P.Util where

import           Control.Monad.Error (throwError)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import           Data.List (unfoldr)

import           Data.Text (unpack)
import           Data.Text.Encoding (encodeUtf8)
import           Data.String (fromString)
import           Data.Char (ord)
import           Data.Tuple (swap)
import           Data.Word (Word8)

import           Data.Binary.IEEE754
import           Data.Binary.Put (runPut)
import           Data.Binary.Get (runGet)

import           Codec.Crypto.RSA hiding (sign, verify)
import qualified Codec.Crypto.RSA as RSA (sign, verify)
import           Codec.Crypto.AES
import           Crypto.Random (CryptoRandomGen, genBytes)

import           P2P
import           P2P.Types

-- Deal with mixtures of strict and lazy ByteStrings

toLazy :: BS.ByteString -> LBS.ByteString
toLazy = LBS.fromChunks . return

fromLazy :: LBS.ByteString -> BS.ByteString
fromLazy = BS.concat . LBS.toChunks

wrapLazy :: (LBS.ByteString -> LBS.ByteString) -> BS.ByteString -> BS.ByteString
wrapLazy f = fromLazy . f . toLazy

-- Wrapper functions for Codec.Crypto.RSA

encryptRSA :: CryptoRandomGen g => g -> PublicKey -> BS.ByteString -> (BS.ByteString, g)
encryptRSA g pk bs = let (res, g') = encrypt g pk (toLazy bs) in (fromLazy res, g')

decryptRSA :: PrivateKey -> BS.ByteString -> BS.ByteString
decryptRSA = wrapLazy . decrypt

sign' :: PrivateKey -> BS.ByteString -> BS.ByteString
sign' = wrapLazy . RSA.sign

verify' :: PublicKey -> BS.ByteString -> BS.ByteString -> Bool
verify' pk msg sig = RSA.verify pk (toLazy msg) (toLazy sig)

-- Wrapper functions for Codec.Crypto.AES

encryptAES :: AESKey -> BS.ByteString -> P2P BS.ByteString
encryptAES key bs = withRandomGen $ \gen ->
  case genBytes 16 gen of
    Left e        -> throwError $ "IV generation failed: " ++ show e
    Right (iv, g) -> return (iv `BS.append` crypt' CFB key iv Encrypt bs, g)

decryptAES :: AESKey -> BS.ByteString -> BS.ByteString
decryptAES key msg = crypt' CFB key iv Decrypt bs
  where (iv, bs) = BS.splitAt 16 msg

-- Wrapper functions for random key generation

genKeyPair :: P2P (PublicKey, PrivateKey)
genKeyPair = withRandomGen $ \gen ->
  let (pub, priv, new) = generateKeyPair gen 2048
  in  return ((pub, priv), new)

genAESKey :: P2P AESKey
genAESKey = withRandomGen $ \gen ->
  case genBytes 32 gen of
    Left e  -> throwError $ "AES key generation failed: " ++ show e
    Right x -> return x

-- Wrapper functions for the Context

getTargetId :: Context -> P2P Id
getTargetId = fromEither . maybe (Left "No target ID in current context") Right . targetId

getTargetAddr :: Context -> P2P Address
getTargetAddr = fromEither . maybe (Left "No target address in current context") Right . targetAddr

getTargetKey :: Context -> P2P AESKey
getTargetKey = fromEither . maybe (Left "No target key in current context") Right . targetKey

getLastField :: Context -> P2P BS.ByteString
getLastField = fromEither . maybe (Left "No previously serialized field") Right . lastField

-- Helper functions

fromMaybe :: Maybe a -> P2P a
fromMaybe Nothing  = throwError "Nothing"
fromMaybe (Just p) = return p

fromEither :: Either String r -> P2P r
fromEither (Left s)  = throwError s
fromEither (Right r) = return r

fromEither' :: Show s => Either s r -> P2P r
fromEither' (Left s)  = throwError $ show s
fromEither' (Right r) = return r

isJust :: Maybe a -> Bool
isJust (Just _) = True
isJust Nothing  = False

pack' :: String -> BS.ByteString
pack' = encodeUtf8 . fromString

ord' :: Char -> Word8
ord' = fromIntegral . ord

-- Convert a number to and from base 256 representation

toWord8 :: Integral a => a -> [Word8]
toWord8 = map fromIntegral . unfoldr f
  where f 0 = Nothing
        f n = Just . swap $ n `divMod` 256

fromWord8 :: Integral a => [Word8] -> a
fromWord8 = foldr (\a b -> a + 256*b) 0 . map fromIntegral

encIntegral :: Integral a => a -> BS.ByteString
encIntegral = BS.pack . toWord8

decIntegral :: Integral a => BS.ByteString -> a
decIntegral = fromWord8 . BS.unpack

-- Convert a double to and from bytestrings

encDouble :: Double -> BS.ByteString
encDouble = fromLazy . runPut . putFloat64le

decDouble :: BS.ByteString -> Double
decDouble = runGet getFloat64le . toLazy

-- Higher order composition

(.:) = (.).(.)
(.::) = (.:).(.:)
