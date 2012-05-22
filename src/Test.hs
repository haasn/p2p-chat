module Main where

import           Codec.Crypto.RSA (generateKeyPair)

import           Control.Monad.Error (runErrorT)
import           Control.Monad.State.Strict (get, put, evalStateT)
import           Control.Monad.Trans (liftIO)
import           Control.Monad.Writer (runWriterT)

import           Crypto.Random (newGenIO, SystemRandom)

import qualified Data.Map as Map

import           P2P.Crypto
import           P2P.Types
import           P2P.Serializing()
import           P2P.Util
import           P2P.Math

roundCheck :: (Serializable a, Eq a) => a -> P2P Bool
roundCheck a = do
  enc <- encode a
  liftIO $ putStrLn (read (show enc) :: String)
  let dec = decode enc
  liftIO $ dec `seq` putStrLn "-----"

  return $ a == dec

showOutput :: String -> P2P Bool
showOutput s = liftIO (putStrLn s >> putStrLn "-----") >> return True

tests :: P2P [Bool]
tests = do
  state <- get
  key   <- genAESKey
  let ctx = (context state) { ctxKey = Just key }
  let pub = pubKey state
  put $ state { context = ctx }

  sequence
    [ roundCheck (12345 :: Integer)

    , roundCheck $ Base64 (12345 :: Integer)
    , roundCheck $ pack "Hello, world!"

    , roundCheck "Hello, world!"
    , roundCheck $ Base64 (0.12345 :: Double)

    , roundCheck TGlobal
    , roundCheck Exact
    , roundCheck Approx

    , roundCheck MGlobal
    , roundCheck Channel
    , roundCheck Single

    , roundCheck (Nothing :: Maybe Integer)
    , roundCheck $ Just (12345 :: Integer)

    , roundCheck $ Base64 pub

    -- Routing header tests

    , roundCheck $ Target TGlobal Nothing
    , roundCheck $ Target Approx (Just (Base64 0.5))
    , roundCheck $ Version (Base64 1)
    , roundCheck $ Support (Base64 2)
    , roundCheck $ Drop (Base64 0.12345)
    , roundCheck Identify
    , roundCheck $ IAm (Base64 pub) (Base64 0.12345) (Base64 1234)

    -- Content tests

    --, roundCheck $ Message MGlobal (pack' "Hello, world!") Signature
    --, roundCheck $ Message Single  (pack' "Hello, world!") Signature

    , roundCheck $ WhoIs (Base64 "nand")
    , roundCheck $ ThisIs (Base64 "nand") (Base64 pub)
    , roundCheck $ NoExist (Base64 "nand")
    , roundCheck $ Exist (Base64 "nand")

    , roundCheck $ WhereIs (Base64 pub)
    , roundCheck $ HereIs (Base64 pub) (Base64 0.12345)
    , roundCheck $ NotFound (Base64 pub)

    -- Hashing checks
    , showOutput $ show (hashId pub)
    , roundCheck $ Base64 (chanKey "#foobar")
    ]

main :: IO ()
main = do
  state <- newState
  res   <- runErrorT (runWriterT $ evalStateT tests state)
  print res

newState :: IO P2PState
newState = do
  gen <- newGenIO :: IO SystemRandom
  let (pub, priv, newgen) = generateKeyPair gen 2048
  return P2PState
    { cwConn    = []
    , ccwConn   = []
    , idTable   = Map.empty
    , locTable  = Map.empty
    , keyTable  = Map.empty
    , pubKey    = pub
    , privKey   = priv
    , homeAddr  = 0.1234
    , homePort  = 1234
    , randomGen = newgen
    , context   = Context (Just pub) (Just 0.12345) Nothing Nothing Nothing True
    }
