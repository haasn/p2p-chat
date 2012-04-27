module P2P.Math where

import Data.Fixed (mod')

import Codec.Crypto.RSA (PublicKey, public_n)

import P2P.Types

-- The hashing function for calculating DHT entry positions

hash :: PublicKey -> Address
hash h = (fromIntegral $ public_n h `mod` 2^64) / 2^64

-- The directional computation algorithm

dir :: Address -> Address -> Direction
dir from to
  | x > 1            = CCW
  | x > 0 && x < 0.5 = CCW
  | otherwise        = CW
    where x = to - from + 0.5

dist :: Address -> Address -> Double
dist a b = min d (1-d)
  where d = abs (a - b)
