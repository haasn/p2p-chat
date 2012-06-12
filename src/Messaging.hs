module P2P.Messaging where

import           P2P
import           P2P.Crypto
import           P2P.Queue
import           P2P.Sending
import           P2P.Types
import           P2P.Util

-- Send a message to a user with given name

message :: Name -> String -> P2P ()
message name body = withName name $ \addr -> do
  id  <- getId' name
  key <- ensureKey id
  setContextKey key
  sendExact [mkSingle body] addr

ensureKey :: Id -> P2P AESKey
ensureKey id = do
  key <- getKey id
  case key of
    Just k  -> return k
    Nothing -> genKey id

genKey :: Id -> P2P AESKey
genKey id = do
  setContextId id
  addr <- getAddr' id
  key  <- genAESKey
  sendExact [mkKey key] addr
  insertKey id key
  return key


-- Send a message to the channel with given name

channel :: String -> String -> P2P ()
channel name body = do
  setContextKey (chanKey name)
  sendGlobal [mkChannel body]

-- Send a message globally

global :: String -> P2P ()
global = sendGlobal . return . mkGlobal
