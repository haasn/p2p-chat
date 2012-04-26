module P2P.Util where

import           Control.Monad.Error (throwError)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import           Data.Text (unpack)
import           Data.Text.Encoding (encodeUtf8)
import           Data.String (fromString)
import           Data.Char (ord)

import           Data.Word (Word8)

import           Codec.Crypto.RSA
import           Codec.Crypto.AES
import           Crypto.Random (CryptoRandomGen, genBytes)

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
sign' = wrapLazy . sign

verify' :: PublicKey -> BS.ByteString -> BS.ByteString -> Bool
verify' pk msg sig = verify pk (toLazy msg) (toLazy sig)

-- Wrapper functions for Codec.Crypto.AES

encryptAES :: CryptoRandomGen g => g -> AESKey -> BS.ByteString -> (BS.ByteString, g)
encryptAES g key bs = (iv `BS.append` crypt' CFB key iv Encrypt bs, g')
  where
    (iv, g') = case genBytes 16 g of
      Left e  -> error $ "IV generation failed: " ++ show e
      Right r -> r

decryptAES :: AESKey -> BS.ByteString -> BS.ByteString
decryptAES key msg = crypt' CFB key iv Decrypt bs
  where (iv, bs) = BS.splitAt 16 msg

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
