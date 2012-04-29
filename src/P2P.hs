module P2P where

import           Network (HostName)

import           Crypto.Random (SystemRandom)
import           Control.Monad.State.Strict
import           Control.Monad (when, unless)

import qualified Data.Map as Map
import qualified Data.Foldable as F (forM_)
import           Data.Maybe (isJust)
import           Data.ByteString (ByteString)
import           Data.List (find)

import           P2P.Types
import           P2P.Math

import           GHC.IO.Handle

-- Wrapper functions for the global state

withRandomGen :: (SystemRandom -> P2P (a, SystemRandom)) -> P2P a
withRandomGen f = do
  state <- get
  (res, gen) <- f $ randomGen state
  put $ state { randomGen = gen }
  return res

-- Connection functions

addConnection :: Handle -> HostName -> Id -> Address -> P2P ()
addConnection h host id adr = do
  exist <- findDirection h
  case exist of
    Nothing  -> modify (insertConnection $ Connection h id adr host)
    Just CW  -> modify (\st -> st { cwConn  = updateConn h id adr $ cwConn  st })
    Just CCW -> modify (\st -> st { ccwConn = updateConn h id adr $ ccwConn st })

delConnection :: Handle -> P2P ()
delConnection h =
  modify $ \st -> st { cwConn = del (cwConn st), ccwConn = del (ccwConn st) }
   where del = filter (not . (== h) . socket)

findDirection :: Handle -> P2P (Maybe Direction)
findDirection h = do
  state <- get
  case find (\c -> socket c == h) (cwConn  state) of
    Just _  -> return (Just CW)
    Nothing -> case find (\c -> socket c == h) (ccwConn state) of
      Just _  -> return (Just CCW)
      Nothing -> return Nothing

findConnection :: Handle -> P2P (Maybe Connection)
findConnection h = do
  state <- get
  return $ find (\c -> socket c == h) (cwConn state ++ ccwConn state)

insertConnection :: Connection -> P2PState -> P2PState
insertConnection c st =
  case dir (homeAddr st) (remoteAddr c) of
    CW  -> st { cwConn  = insert (cwConn  st) }
    CCW -> st { ccwConn = insert (ccwConn st) }
  where
    insert :: [Connection] -> [Connection]
    insert cs = let (l,g) = span (\p -> dista p < distb) cs in l ++ [c] ++ g
      where dista p = dist (homeAddr st) (remoteAddr p)
            distb   = dist (homeAddr st) (remoteAddr c)

updateConn :: Handle -> Id -> Address -> [Connection] -> [Connection]
updateConn _ _ _ [] = []
updateConn h id adr (x:xs)
  | socket x == h = x { remoteId = id, remoteAddr = adr } : xs
  | otherwise     = x : updateConn h id adr xs

-- Context functions

withContext :: (Context -> P2P a) -> P2P a
withContext f = gets context >>= f

setContext :: Context -> P2P ()
setContext ctx = modify $ \state -> state { context = ctx }

modifyContext :: (Context -> Context) -> P2P ()
modifyContext f = withContext $ setContext . f

resetContext :: P2P ()
resetContext = setContext nullContext

setContextId :: Id -> P2P ()
setContextId i = modifyContext $ \ctx -> ctx { ctxId = Just i }

setContextAddr :: Address -> P2P ()
setContextAddr a = modifyContext $ \ctx -> ctx { ctxAddr = Just a }

setContextKey :: AESKey -> P2P ()
setContextKey k = modifyContext $ \ctx -> ctx { ctxKey = Just k }

setIsMe :: P2P ()
setIsMe = modifyContext $ \ctx -> ctx { ctxIsMe = True }

getIsMe :: P2P Bool
getIsMe = withContext (return . ctxIsMe)

setLastField :: ByteString -> P2P ()
setLastField f = modifyContext $ \ctx -> ctx { lastField = Just f }

loadContext :: Id -> P2P ()
loadContext id = do
  state <- get
  setContextId id
  Map.lookup id (keyTable state) `F.forM_` setContextKey
  Map.lookup id (locTable state) `F.forM_` setContextAddr

-- Map processing

insertAddr :: Id -> Address -> P2P ()
insertAddr id addr = modify $ \st -> st { locTable = Map.insert id addr (locTable st) }

forgetAddr :: Address -> P2P ()
forgetAddr addr = modify $ \st -> st { locTable = Map.filter (/= addr) (locTable st) }

insertId :: Name -> Id -> P2P ()
insertId name id = modify $ \st -> st { idTable = Map.insert name id (idTable st) }

insertKey :: Id -> AESKey -> P2P ()
insertKey id key = modify $ \st -> st { keyTable = Map.insert id key (keyTable st) }

-- Packet processing functions

isTarget (Target _ _) = True
isTarget _            = False

isSource (Source _ _) = True
isSource _            = False

isIdentify Identify = True
isIdentify _        = False

isIAm (IAm _ _) = True
isIAm _         = False
