module P2P.Queue where

import           Control.Monad.State.Strict (get, put)

import           Data.List (partition)

import           P2P
import           P2P.Sending
import           P2P.Types

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
  id <- getId' name

  mapM_ (\(NeedId _ f) -> f id) $ reverse match
  return rest

  where
    f (NeedAddr _ _) = False
    f (NeedId   n _) = n == name

hasAddr :: Id -> P2P ()
hasAddr id = modifyQueue $ \queue -> do
  let (match, rest) = partition f queue
  addr <- getAddr' id

  mapM_ (\(NeedAddr _ f) -> f addr) $ reverse match
  return rest

  where
    f (NeedId   _ _) = False
    f (NeedAddr i _) = i == id

-- Functions to perform DHT lookups and/or delay processing

withId :: Id -> (Address -> P2P ()) -> P2P ()
withId id f = do
  adr <- getAddr id
  case adr of
    Just a  -> f a
    Nothing -> do
      enqueue $ NeedAddr id f
      sendWhereIs id

withName :: Name -> (Address -> P2P ()) -> P2P ()
withName name f = do
  id <- getId name
  case id of
    Just i  -> withId i f
    Nothing -> do
      enqueue $ NeedId name (`withId` f)
      sendWhoIs name
