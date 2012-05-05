module P2P.Math where

import Data.Bits (xor)
import Data.Char (ord)
import Data.List (unfoldr, foldl')
import Data.Tuple (swap)

import Codec.Crypto.RSA (PublicKey, public_n)

import P2P.Types

-- The hashing function for calculating DHT entry positions

hashId :: Id -> Address
hashId i = fromIntegral (public_n i `mod` 2^64) / 2^64

hashName :: Name -> Address
hashName = (/32) . fromIntegral . (`mod` 32) . foldl' xor 0 . map ord

-- The directional computation algorithms

dir :: Address -> Address -> Direction
dir from to
  | x > 1            = CCW
  | x > 0 && x < 0.5 = CCW
  | otherwise        = CW
    where x = to - from + 0.5

dist :: Address -> Address -> Double
dist a b = min d (1-d)
  where d = abs (a - b)

-- Convert a number to and from base 256 representation

toWord8 :: (Integral a, Integral b) => a -> [b]
toWord8 = map fromIntegral . unfoldr f
  where f 0 = Nothing
        f n = Just . swap $ n `divMod` 256

fromWord8 :: (Integral a, Integral b) => [a] -> b
fromWord8 = foldr ((\a b -> a + 256*b) . fromIntegral) 0
