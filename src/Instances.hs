{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}

module P2P.Instances where

import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (gets)
import           Control.Applicative

import           Codec.Crypto.RSA (PublicKey(..), PrivateKey)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64 (encode, decode)

import           Data.String (fromString)
import           Data.Char (toLower)

import           Data.Text (Text, unpack)
import           Data.Text.Encoding

import qualified Data.Serialize as S

import           P2P
import           P2P.Types
import           P2P.Util

-- Section logic

instance Serializable RSection where
  encode (Target     t a) = sec "TARGET"     [encode t, encode a]
  encode (Source     i s) = sec "SOURCE"     [encode i, sign i]
  encode (SourceAddr a s) = sec "SOURCEADDR" [encode a, sign a]
  encode (Version    v  ) = sec "VERSION"    [encode v]
  encode (Support    v  ) = sec "SUPPORT"    [encode v]
  encode (Drop       a  ) = sec "DROP"       [encode a]

  decode bs = do
    res <- parse bs
    case res of
      ("target", tt:l) -> do
        tt' <- decode tt
        case tt' of
          TGlobal -> return $ Target TGlobal Nothing
          t       -> Target t <$> decode (head l)

      ("source"    , [i,s]) -> Source     <$> decode i <*> verify i s
      ("sourceaddr", [a,s]) -> SourceAddr <$> decode a <*> verify a s
      ("version"   , [v  ]) -> Version    <$> decode v
      ("support"   , [v  ]) -> Support    <$> decode v
      ("drop"      , [a  ]) -> Drop       <$> decode a

instance Serializable CSection where
  encode (Key      p s) = sec "KEY"      [encode p, sign p]
  encode (WhoIs      n) = sec "WHOIS"    [encode n]
  encode (ThisIs   n i) = sec "THISIS"   [encode n, encode i]
  encode (NoExist    n) = sec "NOEXIST"  [encode n]
  encode (Register n s) = sec "REGISTER" [encode n, sign n]
  encode (Exist      n) = sec "EXIST"    [encode n]
  encode (WhereIs    i) = sec "WHEREIS"  [encode i]
  encode (HereIs   i a) = sec "HEREIS"   [encode i, encode a]
  encode (NotFound   i) = sec "NOTFOUND" [encode i]
  encode (Update   a s) = sec "UPDATE"   [encode a, sign a]

  decode bs = do
    res <- parse bs
    case res of
      ("key"     , [p,s]) -> Key      <$> decode p <*> verify p s
      ("whois"   , [n  ]) -> WhoIs    <$> decode n
      ("thisis"  , [n,i]) -> ThisIs   <$> decode n <*> decode i
      ("noexist" , [n  ]) -> NoExist  <$> decode n
      ("register", [n,s]) -> Register <$> decode n <*> verify n s
      ("exist"   , [n  ]) -> Exist    <$> decode n
      ("whereis" , [i  ]) -> WhereIs  <$> decode i
      ("hereis"  , [i,a]) -> HereIs   <$> decode i <*> decode a
      ("notfound", [i  ]) -> NotFound <$> decode i
      ("update"  , [a,s]) -> Update   <$> decode a <*> verify a s

-- Trivial data types

instance Serializable BS.ByteString where
  encode = return
  decode = return

instance Serializable Text where
  encode = return . encodeUtf8
  decode = fromEither' . decodeUtf8'

instance Serializable String where
  encode   = encode . (fromString :: String -> Text)
  decode b = unpack <$> decode b

instance Serializable Integer where
  encode = return . encIntegral
  decode = return . decIntegral

instance Serializable Double where
  encode = return . encDouble
  decode = return . decDouble

instance Serializable TargetType where
  encode TGlobal = encode "GLOBAL"
  encode Exact   = encode "EXACT"
  encode Approx  = encode "APPROX"

  decode bs = read' <$> decode bs
    where
      read' s = case map toLower s of
        "global" -> TGlobal
        "exact"  -> Exact
        "approx" -> Approx

instance Serializable MessageType where
  encode MGlobal = encode "GLOBAL"
  encode Channel = encode "CHANNEL"
  encode Single  = encode "SINGLE"

  decode bs = read' <$> decode bs
    where
      read' s = case map toLower s of
        "global"  -> MGlobal
        "channel" -> Channel
        "single"  -> Single

instance Serializable s => Serializable (Maybe s) where
  encode Nothing  = return BS.empty
  encode (Just s) = encode s

  decode bs = if BS.length bs == 0
    then return Nothing
    else Just <$> decode bs

instance Serializable PublicKey where
  encode (PublicKey s n e) = return $ BS.concat [encIntegral s, encIntegral n, encIntegral e]

  decode bs = return $ PublicKey size (decIntegral n) (decIntegral e)
    where
      (s,rest) = BS.splitAt 2 bs
      size     = decIntegral s
      (n,e)    = BS.splitAt (fromIntegral size) rest

-- Base64 and encryption logic

instance Serializable s => Serializable (Base64 s) where
  encode (Base64 s) = B64.encode <$> encode s
  decode bs         = Base64 <$> (decode =<< fromEither (B64.decode bs))

instance Serializable s => Serializable (RSA s) where
  encode (RSA s) = do
    pk <- gets context >>= getTargetId
    inner <- encode s
    withRandomGen (\gen -> encryptRSA gen pk inner)

  decode bs = do
    key <- gets privKey
    RSA <$> decode (decryptRSA key bs)

instance Serializable s => Serializable (AES s) where
  encode (AES s) = do
    key <- gets context >>= getTargetKey
    inner <- encode s
    withRandomGen (\gen -> encryptAES gen key inner)

  decode bs = do
    key <- gets context >>= getTargetKey
    AES <$> decode (decryptAES key bs)

-- Parameter grouping logic

group' :: [P2P BS.ByteString] -> P2P BS.ByteString
group' l = (BS.intercalate (pack' " ") . filter (not . BS.null)) <$> sequence l

ungroup' :: BS.ByteString -> [BS.ByteString]
ungroup' = BS.split $ ord' ' '

sec :: String -> [P2P BS.ByteString] -> P2P BS.ByteString
sec c l = group' $ encode c : l

parse' :: [BS.ByteString] -> P2P (String, [BS.ByteString])
parse' []     = throwError "Empty section!"
parse' (x:xs) = do
  cmd <- map toLower <$> decode x
  return (cmd, xs)

parse :: BS.ByteString -> P2P (String, [BS.ByteString])
parse = parse' . ungroup'

-- Section grouping logic

instance Serializable RoutingHeader where
  encode rh = BS.intercalate (pack' "\n") <$> (sequence $ map encode rh)
  decode bs = sequence . map decode $ BS.split (ord' '\n') bs

instance Serializable Content where
  encode rh = BS.intercalate (pack' "\n") <$> (sequence $ map encode rh)
  decode bs = sequence . map decode $ BS.split (ord' '\n') bs

instance Serializable Packet where
  encode (Packet rh c) = BS.concat <$> sequence [encode rh, return $ pack' "\n\n", encode c]
  decode bs = do
    let (rh, c) = BS.breakSubstring (pack' "\n\n") bs
    Packet <$> decode rh <*> decode c

-- Helper functions for RSA serialization

sign :: Serializable s => s -> P2P BS.ByteString
sign s = sign' <$> gets privKey <*> encode s

verify :: BS.ByteString -> BS.ByteString -> P2P Signature
verify m s = do
  m' <- decode m
  (Base64 s') <- decode s
  pk <- gets context >>= getTargetId

  case verify' pk m' s' of
    True  -> return Signature
    False -> throwError "Signature does not match id"
