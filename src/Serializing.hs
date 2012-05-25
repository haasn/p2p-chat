{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}

module P2P.Serializing where

import           Control.Applicative
import           Control.Monad (join)
import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (gets)

import           Crypto.Types.PubKey.RSA (PublicKey(..))

import           Data.Binary.IEEE754
import           Data.Binary.Put (runPut)
import           Data.Binary.Get (runGet)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64 (encode, decode)

import           Data.Char (toLower)
import           Data.String (fromString)
import           Data.Text (Text, unpack)
import           Data.Text.Encoding

import           P2P
import           P2P.Crypto
import           P2P.Math
import           P2P.Types
import           P2P.Util

-- Section coding

instance Serializable RSection where
  encode (Target     t a) = section "TARGET"     [encode t, encode a]
  encode (Source     i _) = section "SOURCE"     [encode i, signLast]
  encode (SourceAddr a _) = section "SOURCEADDR" [encode a, signLast]
  encode (Version    v  ) = section "VERSION"    [encode v]
  encode (Support    v  ) = section "SUPPORT"    [encode v]
  encode (Drop       a  ) = section "DROP"       [encode a]
  encode (IAm      i a p) = section "IAM"        [encode i, encode a, encode p]
  encode (Offer      a  ) = section "OFFER"      [encode a]
  encode (Identify      ) = section "IDENTIFY"   []
  encode (DialIn        ) = section "DIALIN"     []
  encode (Quit          ) = section "QUIT"       []

  encode RUnknown{} = throwError "Trying to encode RUnknown"

  decode bs = case parseSection (splitSection bs) of
    ("target", tt:l) -> case decode tt of
        TGlobal -> Target TGlobal Nothing
        t       -> Target t (decode $ head l)

    ("source"    , [i,s  ]) -> Source (decode i) (Verify i s)
    ("sourceaddr", [a,s  ]) -> SourceAddr (decode a) (Verify a s)
    ("version"   , [v    ]) -> Version (decode v)
    ("support"   , [v    ]) -> Support (decode v)
    ("drop"      , [a    ]) -> Drop (decode a)
    ("iam"       , [i,a,p]) -> IAm (decode i) (decode a) (decode p)
    ("offer"     , [a    ]) -> Offer (decode a)
    ("identify"  , [     ]) -> Identify
    ("dialin"    , [     ]) -> DialIn
    ("quit"      , [     ]) -> Quit

    _ -> RUnknown bs

instance Serializable CSection where
  encode (Message t m _) = section "MESSAGE" [encode t, m', signLast]
    where m' = case t of
                 MGlobal -> encode $ Base64 m
                 _       -> encode $ Base64 (AES m)

  encode (Key      p _) = section "KEY"      [encode p, signLast]
  encode (WhoIs      n) = section "WHOIS"    [encode n]
  encode (ThisIs   n i) = section "THISIS"   [encode n, encode i]
  encode (NoExist    n) = section "NOEXIST"  [encode n]
  encode (Register n _) = section "REGISTER" [encode n, signLast]
  encode (Exist      n) = section "EXIST"    [encode n]
  encode (WhereIs    i) = section "WHEREIS"  [encode i]
  encode (HereIs   i a) = section "HEREIS"   [encode i, encode a]
  encode (NotFound   i) = section "NOTFOUND" [encode i]
  encode (Update   a _) = section "UPDATE"   [encode a, signLast]
  encode (Request     ) = section "REQUEST"  []
  encode (Peer   h p a) = section "PEER"     [encode h, encode p, encode a]

  encode CUnknown{} = throwError "Trying to encode CUnknown"

  decode bs = case parseSection (splitSection bs) of
    ("key"     , [k,s  ]) -> Key (decode k) (Verify k s)
    ("whois"   , [n    ]) -> WhoIs (decode n)
    ("thisis"  , [n,i  ]) -> ThisIs (decode n) (decode i)
    ("noexist" , [n    ]) -> NoExist (decode n)
    ("register", [n,s  ]) -> Register (decode n) (Verify n s)
    ("exist"   , [n    ]) -> Exist (decode n)
    ("whereis" , [i    ]) -> WhereIs (decode i)
    ("hereis"  , [i,a  ]) -> HereIs (decode i) (decode a)
    ("notfound", [i    ]) -> NotFound (decode i)
    ("update"  , [a,s  ]) -> Update (decode a) (Verify a s)
    ("message" , [t,m,s]) -> Message (decode t) m (Verify m s)
    ("request" , [     ]) -> Request
    ("peer"    , [h,p,a]) -> Peer (decode h) (decode p) (decode a)

    _ -> CUnknown bs

-- Trivial data types

instance Serializable ByteString where
  encode = return
  decode = id

instance Serializable Text where
  encode = return . encodeUtf8
  decode = fromRight' . decodeUtf8'

instance Serializable String where
  encode = encode . (fromString :: String -> Text)
  decode = unpack . decode

instance Serializable Integer where
  encode = return . encIntegral
  decode = decIntegral

instance Serializable Double where
  encode = return . encDouble
  decode = decDouble

instance Serializable Port where
  encode = encode . (fromIntegral :: Port -> Integer)
  decode = (fromIntegral :: Integer -> Port) . decode

instance Serializable TargetType where
  encode TGlobal = encode "GLOBAL"
  encode Exact   = encode "EXACT"
  encode Approx  = encode "APPROX"

  decode = read' . decode
    where
      read' s = case map toLower s of
        "global" -> TGlobal
        "exact"  -> Exact
        "approx" -> Approx
        s        -> error $ "Failed parsing TargetType: " ++ s

instance Serializable MessageType where
  encode MGlobal = encode "GLOBAL"
  encode Channel = encode "CHANNEL"
  encode Single  = encode "SINGLE"

  decode = read' . decode
    where
      read' s = case map toLower s of
        "global"  -> MGlobal
        "channel" -> Channel
        "single"  -> Single
        s         -> error $ "Failed parsing MessageType: " ++ s

instance Serializable s => Serializable (Maybe s) where
  encode Nothing  = return BS.empty
  encode (Just s) = encode s

  decode bs = if BS.length bs == 0
    then Nothing
    else Just (decode bs)

instance Serializable PublicKey where
  encode (PublicKey s n e) = return $
    BS.concat [trim 4 $ encIntegral s, trim 4 $ encIntegral e, encIntegral n]

  decode bs = PublicKey (decIntegral s) (decIntegral n) (decIntegral e)
    where
      (s,rest) = BS.splitAt 4 bs
      (e,n)    = BS.splitAt 4 rest

-- Base64 and encryption logic

instance Serializable s => Serializable (Base64 s) where
  encode (Base64 s) = B64.encode <$> encode s
  decode            = Base64 . decode . fromRight . B64.decode

instance Serializable s => Serializable (RSA s) where
  encode (RSA s)   = join $ encryptRSA <$> getContextId <*> encode s
  encode (UnRSA _) = error "Trying to encode UnRSA"
  decode           = UnRSA

instance Serializable s => Serializable (AES s) where
  encode (AES s)   = join $ encryptAES <$> getContextKey <*> encode s
  encode (UnAES _) = error "Trying to encode UnAES"
  decode           = UnAES

-- Parameter grouping logic

joinSection :: [P2P ByteString] -> P2P ByteString
joinSection l = (BS.intercalate (pack " ") . filter (not . BS.null)) <$> mapM upd l
  where
    upd :: P2P ByteString -> P2P ByteString
    upd a = do
      res <- a
      setLastField res
      return res

splitSection :: ByteString -> [ByteString]
splitSection = BS.split $ ord ' '

parseSection :: [ByteString] -> (String, [ByteString])
parseSection []     = ([], [])
parseSection (x:xs) = (map toLower (decode x), xs)

section :: String -> [P2P ByteString] -> P2P ByteString
section c l = joinSection $ encode c : l

-- Section grouping logic

instance Serializable RoutingHeader where
  encode rh = BS.intercalate (pack ";") <$> mapM encode rh
  decode    = map decode . BS.split (ord ';')

instance Serializable Content where
  encode rh = BS.intercalate (pack ";") <$> mapM encode rh
  decode    = map decode . BS.split (ord ';')

instance Serializable Packet where
  encode (Packet rh c) = BS.concat <$> sequence
    [encode rh, return $ pack "|", encode c]

                                 -- Drop the ‘|’ too
  decode bs = Packet (decode rh) tailsec
    where
      (rh, c) = BS.breakSubstring (pack "|") bs
      tailsec
        | BS.null c = []
        | otherwise = decode $ BS.tail c


-- Helper function for RSA serialization

signLast :: P2P ByteString
signLast = (Base64 .: sign <$> gets privKey <*> getLastField) >>= encode

-- Serialization functions for numeric types

encIntegral :: Integral a => a -> ByteString
encIntegral = BS.pack . toWord8

decIntegral :: Integral a => ByteString -> a
decIntegral = fromWord8 . BS.unpack

encDouble :: Double -> ByteString
encDouble = fromLazy . runPut . putFloat64le

decDouble :: ByteString -> Double
decDouble = runGet getFloat64le . toLazy
