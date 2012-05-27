module P2P.Queue where

import           Control.Monad.State.Strict (get, put)
import           Control.Monad.Writer (tell)

import           Data.List (partition)

import           Network (HostName)

import           P2P
import           P2P.Sending
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
  id <- getId' name

  mapM_ (\(NeedId _ f) -> f id) $ reverse match
  return rest

  where
    f (NeedId   n _) = n == name
    f NeedAddr{}     = False
    f NeedPeers{}    = False

hasAddr :: Id -> P2P ()
hasAddr id = modifyQueue $ \queue -> do
  let (match, rest) = partition f queue
  addr <- getAddr' id

  mapM_ (\(NeedAddr _ f) -> f addr) $ reverse match
  return rest

  where
    f NeedId{}       = False
    f (NeedAddr i _) = i == id
    f NeedPeers{}    = False

hasPeers :: [(HostName, Port, Address)] -> P2P ()
hasPeers pl = modifyQueue $ \queue -> do
  let (match, rest) = removeFirst f queue

  case match of
    Just (NeedPeers a) -> a pl
    _                  -> tell $ map (\(a,b,_) -> (a,b)) pl

  return rest

  where
    f NeedId{}    = False
    f NeedAddr{}  = False
    f NeedPeers{} = True

-- Functions to delete delayed actions from the queue for which no appropriate
-- information could be found, eg. due to a NOEXIST or NOTFOUND.

noId :: Name -> P2P ()
noId name = modifyQueue $ return . filter f
  where
    f (NeedId   n _) = n /= name
    f NeedAddr{}     = True
    f NeedPeers{}    = True

noAddr :: Id -> P2P ()
noAddr id = modifyQueue $ return . filter f
  where
    f NeedId{}       = True
    f (NeedAddr i _) = i /= id
    f NeedPeers{}    = True

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

withPeers :: ([(HostName, Port, Address)] -> P2P ()) -> P2P ()
withPeers = enqueue . NeedPeers
