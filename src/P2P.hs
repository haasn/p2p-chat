module P2P where

import           Crypto.Random (SystemRandom)
import           Control.Monad.State.Strict

import           P2P.Types

-- Wrapper functions for the global state

withRandomGen :: (SystemRandom -> (a, SystemRandom)) -> P2P a
withRandomGen f = do
  state <- get
  let (res, gen) = f $ randomGen state
  put $ state { randomGen = gen }
  return res

