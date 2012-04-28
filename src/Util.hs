module P2P.Util where

import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (gets)

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import           Data.List (unfoldr)

import           Data.Text()
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
import           Codec.Digest.SHA (Length(..))
import qualified Codec.Digest.SHA as SHA
import           Crypto.Random (CryptoRandomGen, genBytes)

import           P2P
import           P2P.Types

-- Deal with mixtures of strict and lazy ByteStrings

toLazy :: ByteString -> LBS.ByteString
toLazy = LBS.fromChunks . return

fromLazy :: LBS.ByteString -> ByteString
fromLazy = BS.concat . LBS.toChunks

wrapLazy :: (LBS.ByteString -> LBS.ByteString) -> ByteString -> ByteString
wrapLazy f = fromLazy . f . toLazy

-- Wrapper functions for Codec.Crypto.RSA

encryptRSA :: PublicKey -> ByteString -> P2P ByteString
encryptRSA pk bs = withRandomGen $ \gen ->
  let (res, g) = encrypt gen pk (toLazy bs) in return (fromLazy res, g)

decryptRSA :: PrivateKey -> ByteString -> ByteString
decryptRSA = wrapLazy . decrypt

sign' :: PrivateKey -> ByteString -> ByteString
sign' = wrapLazy . RSA.sign

verify' :: PublicKey -> ByteString -> ByteString -> Bool
verify' pk msg sig = RSA.verify pk (toLazy msg) (toLazy sig)

-- Wrapper functions for Codec.Crypto.AES

encryptAES :: AESKey -> ByteString -> P2P ByteString
encryptAES key bs = withRandomGen $ \gen ->
  case genBytes 16 gen of
    Left e        -> throwError $ "IV generation failed: " ++ show e
    Right (iv, g) -> return (iv `BS.append` crypt' CFB key iv Encrypt bs, g)

decryptAES :: AESKey -> ByteString -> ByteString
decryptAES key msg = crypt' CFB key iv Decrypt bs
  where (iv, bs) = BS.splitAt 16 msg

-- Wrapper functions for Codec.Digest.SHA

chanKey :: Name -> ByteString
chanKey = SHA.hash SHA256 . encodeUtf8 . fromString

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

getContextId :: P2P Id
getContextId = gets context >>= fromEither . maybe (Left "No target ID in current context") Right . ctxId

getContextAddr :: P2P Address
getContextAddr = gets context >>= fromEither . maybe (Left "No target address in current context") Right . ctxAddr

getContextKey :: P2P AESKey
getContextKey = gets context >>= fromEither . maybe (Left "No target key in current context") Right . ctxKey

getLastField :: P2P ByteString
getLastField = gets context >>= fromEither . maybe (Left "No previously serialized field") Right . lastField

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

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

pack' :: String -> ByteString
pack' = encodeUtf8 . fromString

ord' :: Char -> Word8
ord' = fromIntegral . ord

-- Convert a number to and from base 256 representation

toWord8 :: Integral a => a -> [Word8]
toWord8 = map fromIntegral . unfoldr f
  where f 0 = Nothing
        f n = Just . swap $ n `divMod` 256

fromWord8 :: Integral a => [Word8] -> a
fromWord8 = foldr ((\a b -> a + 256*b) . fromIntegral) 0

encIntegral :: Integral a => a -> ByteString
encIntegral = BS.pack . toWord8

decIntegral :: Integral a => ByteString -> a
decIntegral = fromWord8 . BS.unpack

-- Convert a double to and from bytestrings

encDouble :: Double -> ByteString
encDouble = fromLazy . runPut . putFloat64le

decDouble :: ByteString -> Double
decDouble = runGet getFloat64le . toLazy

-- Higher order composition

(.:) :: (c -> d) -> (a -> b -> c) -> a -> b -> d
(.:) = (.).(.)

-- Wrappers for section constructors

mkTarget tt addr = Target tt (Base64 `fmap` addr)
mkSource id = Source (Base64 id) Signature
mkSourceAddr addr = SourceAddr (Base64 addr) Signature
mkVersion v = Version (Base64 v)
mkSupport v = Support (Base64 v)
mkDrop addr = Drop (Base64 addr)
mkIAm id addr = IAm (Base64 id) (Base64 addr)

mkMessage mt msg = Message mt (pack' msg) Signature
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
