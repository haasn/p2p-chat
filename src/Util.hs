module P2P.Util where

import           Control.Monad.Error (throwError)

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import qualified Data.Char (ord)
import           Data.List (find)
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

wrapError :: P2P (Maybe a) -> String -> P2P a
wrapError act err = act >>= maybe (throwError err) return

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _        = False

pack :: String -> ByteString
pack = encodeUtf8 . fromString

ord :: Integral a => Char -> a
ord = fromIntegral . Data.Char.ord

-- Extract the first element satisfying a predicate from a list

removeFirst :: (a -> Bool) -> [a] -> (Maybe a, [a])
removeFirst f xs = (find f xs, dropFirst f xs)

dropFirst :: (a -> Bool) -> [a] -> [a]
dropFirst _ [] = []
dropFirst f (x:xs)
  | f x = xs
  | otherwise = x : dropFirst f xs

-- Wrappers for section constructors

mkTarget tt addr = Target tt (Base64 `fmap` addr)
mkSource id addr = Source (Base64 id) Signature (Base64 addr) Signature
mkVersion v = Version (Base64 v)
mkSupport v = Support (Base64 v)
mkDrop addr = Drop (Base64 addr)
mkIAm id addr port = IAm (Base64 id) (Base64 addr) (Base64 port)
mkOffer addr = Offer (Base64 addr)

mkGlobal msg = Global (Base64 msg) Signature
mkChannel msg = Channel (Base64 (AES msg)) Signature
mkSingle msg = Single (Base64 (AES msg)) Signature
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
mkPeer host port addr = Peer (Base64 host) (Base64 port) (Base64 addr)

-- Helper functions for pretty printing

showLine :: String -> String
showLine s = " - " ++ s ++ "\n"

showC :: Connection -> String
showC c =
  showId (remoteId c) ++ " @ " ++ show (remoteAddr c) ++
  " (" ++ hostName c ++ ":" ++ show (hostPort c) ++ ")"

showIT :: (Name, Id) -> String
showIT (name, id) = name ++ " -> " ++ showId id

showLT :: (Id, Address) -> String
showLT (id, adr) = showId id ++ " -> " ++ show adr

showKT :: (Id, AESKey) -> String
showKT (id, key) = showId id ++ " -> " ++ show key

showId :: Id -> String
showId id = '#' : show (hashId id)

-- Higher order composition and currying

(.:) :: (c -> d) -> (a -> b -> c) -> a -> b -> d
(.:) = (.).(.)

uncurry3 :: (a1 -> a2 -> a3 -> b) -> (a1,a2,a3) -> b
uncurry3 f (a,b,c) = f a b c
