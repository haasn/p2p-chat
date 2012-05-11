module P2P where

import           Control.Applicative
import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict

import           Crypto.Random (SystemRandom)

import           Data.ByteString (ByteString)
import qualified Data.Foldable as F (forM_)
import           Data.List (find)
import qualified Data.Map as Map

import           GHC.IO.Handle

import           Network (HostName)

import           P2P.Math
import           P2P.Types

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
    Nothing  -> modify (insertConnection  $ Connection h id adr host)
    Just CW  -> modify (\s -> s { cwConn  = updateConn h id adr $ cwConn  s })
    Just CCW -> modify (\s -> s { ccwConn = updateConn h id adr $ ccwConn s })

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

updateCW :: ([Connection] -> P2P [Connection]) -> P2P ()
updateCW f = do
  cs <- gets cwConn >>= f
  modify $ \st -> st { cwConn = cs }

updateCCW :: ([Connection] -> P2P [Connection]) -> P2P ()
updateCCW f = do
  cs <- gets ccwConn >>= f
  modify $ \st -> st { ccwConn = cs }

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

setContextHandle :: (Handle, HostName) -> P2P ()
setContextHandle h = modifyContext $ \ctx -> ctx { ctxHandle = Just h }

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

getsDir :: Direction -> P2P [Connection]
getsDir  CW = gets  cwConn
getsDir CCW = gets ccwConn

getContextId :: P2P Id
getContextId = do
  id <- ctxId <$> gets context
  case id of
    Nothing -> throwError "No remote ID in current context"
    Just i  -> return i

getContextAddr :: P2P Address
getContextAddr = do
  addr <- ctxAddr <$> gets context
  case addr of
    Nothing -> throwError "No remote address in current context"
    Just a  -> return a

getContextKey :: P2P AESKey
getContextKey = do
  key <- ctxKey <$> gets context
  case key of
    Nothing -> throwError "No remote key in current context"
    Just k  -> return k

getContextHandle :: P2P (Handle, HostName)
getContextHandle = do
  handle <- ctxHandle <$> gets context
  case handle of
    Nothing -> throwError "No remote handle in current context"
    Just h  -> return h

getLastField :: P2P ByteString
getLastField = do
  field <- lastField <$> gets context
  case field of
    Nothing -> throwError "No previously serialized field"
    Just f  -> return f

-- Map processing

insertAddr :: Id -> Address -> P2P ()
insertAddr id addr = modify $ \st ->
  st { locTable = Map.insert id addr (locTable st) }

forgetAddr :: Address -> P2P ()
forgetAddr addr = modify $ \st ->
  st { locTable = Map.filter (/= addr) (locTable st) }

insertId :: Name -> Id -> P2P ()
insertId name id = modify $ \st ->
  st { idTable = Map.insert name id (idTable st) }

insertKey :: Id -> AESKey -> P2P ()
insertKey id key = modify $ \st ->
  st { keyTable = Map.insert id key (keyTable st) }

-- Packet processing functions

isSource :: RSection -> Bool
isSource Source{} = True
isSource _        = False

isTarget :: RSection -> Bool
isTarget Target{} = True
isTarget _        = False

isNoRoute :: RSection -> Bool
isNoRoute rsec = case rsec of
  Identify -> True
  IAm{}    -> True
  Peer{}   -> True
  Panic    -> True

  _ -> False

isValid :: RoutingHeader -> Bool
isValid rh = any isSource rh && any isTarget rh
