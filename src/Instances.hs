{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}

module P2P.Instances where

import           Control.Monad (join)
import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (gets)
import           Control.Applicative

import           Codec.Crypto.RSA (PublicKey(..))

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64 (encode, decode)

import           Data.String (fromString)
import           Data.Char (toLower)

import           Data.Text (Text, unpack)
import           Data.Text.Encoding

import           P2P
import           P2P.Types
import           P2P.Util

-- Section logic

instance Serializable RSection where
  encode (Target     t a) = sec "TARGET"     [encode t, encode a]
  encode (Source     i _) = sec "SOURCE"     [encode i, sign]
  encode (SourceAddr a _) = sec "SOURCEADDR" [encode a, sign]
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
  encode (Message t m s) = sec "MESSAGE" [encode t, m', sign]
    where m' = case t of
            MGlobal -> encode $ Base64 m
            _       -> encode $ Base64 (AES m)

  encode (Key      p _) = sec "KEY"      [encode p, sign]
  encode (WhoIs      n) = sec "WHOIS"    [encode n]
  encode (ThisIs   n i) = sec "THISIS"   [encode n, encode i]
  encode (NoExist    n) = sec "NOEXIST"  [encode n]
  encode (Register n _) = sec "REGISTER" [encode n, sign]
  encode (Exist      n) = sec "EXIST"    [encode n]
  encode (WhereIs    i) = sec "WHEREIS"  [encode i]
  encode (HereIs   i a) = sec "HEREIS"   [encode i, encode a]
  encode (NotFound   i) = sec "NOTFOUND" [encode i]
  encode (Update   a _) = sec "UPDATE"   [encode a, sign]

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

      ("message" , [t,m,s]) -> do
        mt <- decode t
        case mt of
          MGlobal -> do
            (Base64 msg) <- decode m
            Message mt msg <$> verify m s

          _       -> do
            (Base64 (AES msg)) <- decode m
            Message mt msg <$> verify m s

-- Trivial data types

instance Serializable ByteString where
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
  encode (RSA s) = join $ encryptRSA <$> (gets context >>= getTargetId) <*> encode s

  decode bs = do
    key <- gets privKey
    RSA <$> decode (decryptRSA key bs)

instance Serializable s => Serializable (AES s) where
  encode (AES s) = join $ encryptAES <$> (gets context >>= getTargetKey) <*> encode s

  decode bs = do
    key <- gets context >>= getTargetKey
    AES <$> decode (decryptAES key bs)

-- Parameter grouping logic

group' :: [P2P ByteString] -> P2P ByteString
group' l = (BS.intercalate (pack' " ") . filter (not . BS.null)) <$> mapM upd l
  where
    upd :: P2P ByteString -> P2P ByteString
    upd a = do
      res <- a
      setLastField res
      return res

ungroup' :: ByteString -> [ByteString]
ungroup' = BS.split $ ord' ' '

sec :: String -> [P2P ByteString] -> P2P ByteString
sec c l = group' $ encode c : l

parse' :: [ByteString] -> P2P (String, [ByteString])
parse' []     = throwError "Empty section!"
parse' (x:xs) = do
  cmd <- map toLower <$> decode x
  return (cmd, xs)

parse :: ByteString -> P2P (String, [ByteString])
parse = parse' . ungroup'

-- Section grouping logic

instance Serializable RoutingHeader where
  encode rh = BS.intercalate (pack' "\n") <$> mapM encode rh
  decode bs = mapM decode $ BS.split (ord' '\n') bs

instance Serializable Content where
  encode rh = BS.intercalate (pack' "\n") <$> mapM encode rh
  decode bs = mapM decode $ BS.split (ord' '\n') bs

instance Serializable Packet where
  encode (Packet rh c) = BS.concat <$> sequence [encode rh, return $ pack' "\n\n", encode c]
  decode bs = do
    let (rh, c) = BS.breakSubstring (pack' "\n\n") bs
    Packet <$> decode rh <*> decode (BS.drop 2 c) -- drop the \n\n too

-- Helper functions for RSA serialization

sign :: P2P ByteString
sign = (Base64 .: sign' <$> gets privKey <*> (gets context >>= getLastField)) >>= encode

verify :: ByteString -> ByteString -> P2P Signature
verify m s = do
  m' <- decode m
  (Base64 s') <- decode s
  pk <- gets context >>= getTargetId

  if verify' pk m' s'
    then return Signature
    else throwError "Signature does not match id"
