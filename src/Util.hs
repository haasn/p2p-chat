module P2P.Util where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import           Codec.Crypto.RSA
import           Crypto.Random (CryptoRandomGen)

-- Deal with mixtures of strict and lazy ByteStrings

toLazy :: BS.ByteString -> LBS.ByteString
toLazy = LBS.fromChunks . return

fromLazy :: LBS.ByteString -> BS.ByteString
fromLazy = BS.concat . LBS.toChunks

wrapLazy :: (LBS.ByteString -> LBS.ByteString) -> BS.ByteString -> BS.ByteString
wrapLazy f = fromLazy . f . toLazy

-- Wrapper functions for Codec.Crypto.RSA

encrypt' :: CryptoRandomGen g => g -> PublicKey -> BS.ByteString -> (BS.ByteString, g)
encrypt' g pk bs = let (res, g') = encrypt g pk (toLazy bs) in (fromLazy res, g')

decrypt' :: PrivateKey -> BS.ByteString -> BS.ByteString
decrypt' = wrapLazy . decrypt

sign' :: PrivateKey -> BS.ByteString -> BS.ByteString
sign' = wrapLazy . sign

verify' :: PublicKey -> BS.ByteString -> BS.ByteString -> Bool
verify' pk msg sig = verify pk (toLazy msg) (toLazy sig)

-- Helper functions

toMaybe :: Either a b -> Maybe b
toMaybe (Left _)  = Nothing
toMaybe (Right b) = Just b
