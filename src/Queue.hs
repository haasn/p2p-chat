module P2P.Queue where

import           Control.Monad.State.Strict (get, put)

import           Data.List (partition)

import           P2P
import           P2P.Types
import           P2P.Util

-- Functions to modify the queue

modifyQueue :: (Queue -> P2P Queue) -> P2P ()
modifyQueue f = do
  state <- get
  new   <- f (dhtQueue state)
  put $ state { dhtQueue = new }

enqueue :: Delayed -> P2P ()
enqueue d = modifyQueue $ return . (d:)

-- Functions to process queue items given new DHT information

hasId :: Name -> P2P ()
hasId name = modifyQueue $ \queue -> do
  let (match, rest) = partition f queue
  id <- getId name

  mapM_ (\(NeedId _ f) -> f id) $ reverse match
  return rest

  where
    f (NeedAddr _ _) = False
    f (NeedId   n _) = n == name

hasAddr :: Id -> P2P ()
hasAddr id = modifyQueue $ \queue -> do
  let (match, rest) = partition f queue
  addr <- getAddr id

  mapM_ (\(NeedAddr _ f) -> f addr) $ reverse match
  return rest

  where
    f (NeedId   _ _) = False
    f (NeedAddr i _) = i == id

-- Functions to delay processing

waitId :: Id -> (Address -> P2P ()) -> P2P ()
waitId = enqueue .: NeedAddr

waitName :: Name -> (Address -> P2P ()) -> P2P ()
waitName name f = enqueue $ NeedId name (`waitId` f)
