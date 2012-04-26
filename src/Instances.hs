{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}

module P2P.Instances where

import           Control.Monad.State.Strict (gets)

import           Codec.Crypto.RSA (PublicKey, PrivateKey)

import qualified Data.ByteString as BS (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode, decode)

import           Data.String (fromString)

import           Data.Text
import           Data.Text.Encoding

import           P2P
import           P2P.Types
import           P2P.Util

-- Trivial data types

instance Serializable BS.ByteString where
  encode _ = return . id
  decode _ = return . Just

instance Serializable Text where
  encode _ = return . encodeUtf8
  decode _ = return . toMaybe . decodeUtf8'

instance Serializable String where
  encode c   = encode c . (fromString :: String -> Text)
  decode c b = do
    res <- decode c b
    return $ unpack `fmap` res

-- Base64 and encryption logic

instance Serializable s => Serializable (Base64 s) where
  encode c (Base64 s) = B64.encode `fmap` encode c s
  decode c bs         = do
    case B64.decode bs of
      Left  _ -> return Nothing
      Right s -> decode c s

instance Serializable s => Serializable (RSA s) where
  encode c (RSA s) = do
    case keyRSA c of
      Nothing -> fail "No public key in current context!"
      Just pk -> do
        inner <- encode c s
        withRandomGen (\gen -> encrypt' gen pk inner)

  decode c bs = do
    key <- gets privKey
    decode c $ decrypt' key bs

