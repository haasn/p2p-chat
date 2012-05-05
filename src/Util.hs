module P2P.Util where

import           Control.Monad.Error (throwError)

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import           Data.Binary.IEEE754
import           Data.Binary.Put (runPut)
import           Data.Binary.Get (runGet)
import qualified Data.Char (ord)
import           Data.String (fromString)
import           Data.Text()
import           Data.Text.Encoding (encodeUtf8)

import           P2P.Math
import           P2P.Types

-- Deal with mixtures of strict and lazy ByteStrings

toLazy :: ByteString -> LBS.ByteString
toLazy = LBS.fromChunks . return

fromLazy :: LBS.ByteString -> ByteString
fromLazy = BS.concat . LBS.toChunks

wrapLazy :: (LBS.ByteString -> LBS.ByteString) -> ByteString -> ByteString
wrapLazy f = fromLazy . f . toLazy

-- Helper functions

fromMaybe :: Maybe a -> P2P a
fromMaybe Nothing  = throwError "Nothing in fromMaybe"
fromMaybe (Just p) = return p

fromEither :: Either String r -> r
fromEither (Left s)  = error s
fromEither (Right r) = r

fromEither' :: Show s => Either s r -> r
fromEither' (Left s)  = error $ show s
fromEither' (Right r) = r

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

pack :: String -> ByteString
pack = encodeUtf8 . fromString

ord :: Integral a => Char -> a
ord = fromIntegral . Data.Char.ord

encIntegral :: Integral a => a -> ByteString
encIntegral = BS.pack . toWord8

decIntegral :: Integral a => ByteString -> a
decIntegral = fromWord8 . BS.unpack

-- Convert a double to and from bytestrings

encDouble :: Double -> ByteString
encDouble = fromLazy . runPut . putFloat64le

decDouble :: ByteString -> Double
decDouble = runGet getFloat64le . toLazy

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
