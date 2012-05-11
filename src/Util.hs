module P2P.Util where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import qualified Data.Char (ord)
import           Data.String (fromString)
import           Data.Text()
import           Data.Text.Encoding (encodeUtf8)

import           P2P.Types

-- Deal with mixtures of strict and lazy ByteStrings

toLazy :: ByteString -> LBS.ByteString
toLazy = LBS.fromChunks . return

fromLazy :: LBS.ByteString -> ByteString
fromLazy = BS.concat . LBS.toChunks

wrapLazy :: (LBS.ByteString -> LBS.ByteString) -> ByteString -> ByteString
wrapLazy f = fromLazy . f . toLazy

-- Enforce a certain length for a ByteString

trim :: Int -> ByteString -> ByteString
trim n bs
  | len > n   = BS.take n bs
  | len < n   = BS.append bs $ BS.replicate (n - len) 0
  | otherwise = bs
 where
  len = BS.length bs

-- Helper functions

fromRight :: Either String r -> r
fromRight (Left s)  = error s
fromRight (Right r) = r

fromRight' :: Show s => Either s r -> r
fromRight' (Left s)  = error $ show s
fromRight' (Right r) = r

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

pack :: String -> ByteString
pack = encodeUtf8 . fromString

ord :: Integral a => Char -> a
ord = fromIntegral . Data.Char.ord

-- Wrappers for section constructors

mkTarget tt addr = Target tt (Base64 `fmap` addr)
mkSource id = Source (Base64 id) Signature
mkSourceAddr addr = SourceAddr (Base64 addr) Signature
mkVersion v = Version (Base64 v)
mkSupport v = Support (Base64 v)
mkDrop addr = Drop (Base64 addr)
mkIAm id addr = IAm (Base64 id) (Base64 addr)
mkPeer host = Peer (Base64 host)

mkMessage mt msg = Message mt (pack msg) Signature
mkKey k = Key (Base64 (RSA k)) Signature
mkWhoIs n = WhoIs (Base64 n)
mkThisIs n id = ThisIs (Base64 n) (Base64 id)
mkNoExist n = NoExist (Base64 n)
mkRegister n = Register (Base64 n) Signature
mkExist n = Exist (Base64 n)
mkWhereIs id = WhereIs (Base64 id)
mkHereIs id addr = HereIs (Base64 id) (Base64 addr)
mkNotFound id = NotFound (Base64 id)
mkUpdate addr = Update (Base64 addr) Signature

-- Higher order composition

(.:) :: (c -> d) -> (a -> b -> c) -> a -> b -> d
(.:) = (.).(.)
