module P2P where

import           Crypto.Random (SystemRandom)
import           Control.Monad.State.Strict

import           Data.ByteString (ByteString)

import           P2P.Types

import Control.Monad.Error (throwError)

-- Wrapper functions for the global state

withRandomGen :: (SystemRandom -> P2P (a, SystemRandom)) -> P2P a
withRandomGen f = do
  state <- get
  (res, gen) <- f $ randomGen state
  put $ state { randomGen = gen }
  return res

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
