module P2P where

import           Crypto.Random (SystemRandom)
import           Control.Monad.State.Strict

import           Data.ByteString (ByteString)

import           P2P.Types
import           P2P.Math

-- Wrapper functions for the global state

withRandomGen :: (SystemRandom -> P2P (a, SystemRandom)) -> P2P a
withRandomGen f = do
  state <- get
  (res, gen) <- f $ randomGen state
  put $ state { randomGen = gen }
  return res

-- Connection functions

addConnection :: Connection -> P2P ()
addConnection = modify . insertConnection

insertConnection :: Connection -> P2PState -> P2PState
insertConnection c st =
  case dir (homeAddr st) (remoteAddr c) of
    CW  -> st { cwConn  = insert c (cwConn  st) }
    CCW -> st { ccwConn = insert c (ccwConn st) }
  where
    insert :: Connection -> [Connection] -> [Connection]
    insert c cs = let (l,g) = span (\p -> dista p < distb) cs in l ++ [c] ++ g
      where dista p = dist (homeAddr st) (remoteAddr p)
            distb   = dist (homeAddr st) (remoteAddr c)

-- Context functions

withContext :: (Context -> P2P a) -> P2P a
withContext f = gets context >>= f

setContext :: Context -> P2P ()
setContext ctx = modify $ \state -> state { context = ctx }

modifyContext :: (Context -> Context) -> P2P ()
modifyContext f = withContext $ setContext . f

resetContext :: P2P ()
resetContext = setContext nullContext

setTargetId :: Id -> P2P ()
setTargetId i = modifyContext $ \ctx -> ctx { targetId = Just i }

setTargetAddr :: Address -> P2P ()
setTargetAddr a = modifyContext $ \ctx -> ctx { targetAddr = Just a }

setTargetKey :: AESKey -> P2P ()
setTargetKey k = modifyContext $ \ctx -> ctx { targetKey = Just k }

setLastField :: ByteString -> P2P ()
setLastField f = modifyContext $ \ctx -> ctx { lastField = Just f }
