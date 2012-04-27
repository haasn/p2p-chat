module P2P where

import           Crypto.Random (SystemRandom)
import           Control.Monad.State

import           P2P.Types

import Control.Monad.Error (throwError)

-- Wrapper functions for the global state

withRandomGen :: (SystemRandom -> (a, SystemRandom)) -> P2P a
withRandomGen f = do
  state <- get
  let (res, gen) = f $ randomGen state
  put $ state { randomGen = gen }
  return res
