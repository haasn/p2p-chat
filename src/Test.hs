import P2P
import P2P.Types
import P2P.Instances
import P2P.Util

import Control.Monad (join)
import Control.Monad.Trans (liftIO)

import Control.Monad.State.Strict (get, put, evalStateT)
import Control.Monad.Error (runErrorT)

import Crypto.Random (newGenIO, SystemRandom)
import Codec.Crypto.RSA (generateKeyPair)

import qualified Data.Map as Map

roundCheck :: (Serializable a, Eq a) => a -> P2P Bool
roundCheck a = do
  enc <- encode a
  dec <- decode enc

  liftIO $ print enc
  return $ a == dec

tests :: P2P [Bool]
tests = do
  state <- get
  key   <- genAESKey
  let ctx = (context state) { targetKey = Just key }
  let pub = pubKey state
  put $ state { context = ctx }

  sequence
    [ roundCheck $ (12345 :: Integer)
    , roundCheck $ Base64 (12345 :: Integer)
    , roundCheck $ RSA (12345 :: Integer)
    , roundCheck $ Base64 (RSA (12345 :: Integer))
    , roundCheck $ pack' "Hello, world!"

    , roundCheck $ "Hello, world!"
    , roundCheck $ (0.12345 :: Double)

    , roundCheck $ TGlobal
    , roundCheck $ Exact
    , roundCheck $ Approx

    , roundCheck $ MGlobal
    , roundCheck $ Channel
    , roundCheck $ Single

    , roundCheck $ (Nothing :: Maybe Integer)
    , roundCheck $ Just (12345 :: Integer)

    , roundCheck $ pubKey state

    -- Routing header tests

    , roundCheck $ Target TGlobal Nothing
    , roundCheck $ Target Approx (Just (Base64 0.5))
    , roundCheck $ Source (Base64 pub) Signature
    , roundCheck $ SourceAddr (Base64 0.12345) Signature
    , roundCheck $ Version (Base64 1)
    , roundCheck $ Support (Base64 2)
    , roundCheck $ Drop (Base64 0.12345)

    -- Content tests

    , roundCheck $ Message MGlobal (Base64 $ pack' "Hello, world!") Signature
    , roundCheck $ Message Single  (Base64 $ pack' "Hello, world!") Signature

    , roundCheck $ WhoIs (Base64 "nand")
    , roundCheck $ ThisIs (Base64 "nand") (Base64 pub)
    , roundCheck $ NoExist (Base64 "nand")
    , roundCheck $ Register (Base64 "nand") Signature
    , roundCheck $ Exist (Base64 "nand")

    , roundCheck $ WhereIs (Base64 pub)
    , roundCheck $ HereIs (Base64 pub) (Base64 0.12345)
    , roundCheck $ NotFound (Base64 pub)
    , roundCheck $ Update (Base64 0.12345) Signature
    ]

main = join (evalStateT (runErrorT tests) `fmap` newState) >>= print

newState :: IO P2PState
newState = do
  gen <- newGenIO :: IO SystemRandom
  let (pub, priv, newgen) = generateKeyPair gen 2048
  return P2PState
    { rightConn = []
    , leftConn  = []
    , keyTable  = Map.empty
    , locTable  = Map.empty
    , pubKey    = pub
    , privKey   = priv
    , randomGen = newgen
    , context   = Context (Just pub) (Just 0.12345) Nothing Nothing
    }