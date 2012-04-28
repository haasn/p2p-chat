module Main where

import Network

import Codec.Crypto.RSA (generateKeyPair)
import Crypto.Random (newGenIO, SystemRandom)

import Data.Maybe (fromJust)
import Data.List (find)
import Data.Tuple (swap)
import Data.ByteString (ByteString, hGetSome, hGetLine, hPut)
import qualified Data.Map as Map

import Control.Applicative
import Control.Monad (forever, when, unless)
import Control.Monad.State.Strict
import Control.Monad.Error
import Control.Exception (finally)

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar hiding (withMVar)

import GHC.IO.Handle hiding (hGetLine)

import P2P
import P2P.Types
import P2P.Instances
import P2P.Math
import P2P.Util

newState :: IO P2PState
newState = do
  gen <- newGenIO :: IO SystemRandom
  let (pub, priv, newgen) = generateKeyPair gen 2048
  return P2PState
    { cwConn    = []
    , ccwConn   = []
    , idTable   = Map.empty
    , locTable  = Map.empty
    , keyTable  = Map.empty
    , pubKey    = pub
    , privKey   = priv
    , homeAddr  = 0.5
    , randomGen = gen
    , context   = nullContext
    }

main :: IO ()
main = withSocketsDo $ do
  state <- newState
  mvar  <- newMVar state
  sock  <- listenOn (PortNumber 1234)

  (`finally` sClose sock) . forever $ do
    (h, host, port) <- accept sock
    hSetBuffering h NoBuffering

    -- Debugging purposes
    putStrLn $ "[?] Accepted connection from " ++ show host ++ ":" ++ show port

    forkIO $ runThread h host mvar `finally` withMVar mvar (close h)

runThread :: Handle -> HostName -> MVar P2PState -> IO ()
runThread h host m = do
  eof <- hIsEOF h
  unless eof $ do
   -- Read as much as possible
   packet <- hGetLine h
   withMVar m (process h host packet)
   runThread h host m

process :: Handle -> HostName -> ByteString -> P2P ()
process h host bs = do
  p@(Packet rh c) <- decode bs

  -- Check for no route packets
  if any isIdentify rh || any isIAm rh
    then mapM_ (prolog h host) rh
    else getConnection h >>= route bs p
 where
  getConnection :: Handle -> P2P Connection
  getConnection h = do
    conn <- findConnection h
    case conn of
      Nothing -> throwError "No connection found, ignoring packet"
      Just c  -> return c

-- Close a handle

close :: Handle -> P2P ()
close h = do
  liftIO $ hClose h
  delConnection h

-- Evaluate a pre-Connection package

prolog :: Handle -> HostName -> RSection -> P2P ()
prolog h host Identify = do
  myId   <- gets pubKey
  myAddr <- gets homeAddr
  hSend h $ Packet [mkIAm myId myAddr] []

prolog h host (IAm (Base64 id) (Base64 adr)) = addConnection h host id adr

-- Ignore everything else
prolog _ _ _ = return ()

-- Route a post-Connection package

route :: ByteString -> Packet -> Connection -> P2P ()
route bs (Packet rh c) conn = do
  -- Debugging purposes
  liftIO . putStrLn $ show (Packet rh c)

  myId   <- gets pubKey
  myAddr <- gets homeAddr

  let Just (Source (Base64 id) _) = find isSource rh
  let Just (Target tt a) = find isTarget rh

  case tt of
    TGlobal -> do
      unless (id == myId) $ do
        -- send to next CW connection
        conn <- head <$> gets cwConn
        cSendRaw conn bs

    Exact -> do
      let Just (Base64 adr) = a
      unless (adr == myAddr) $ case dir myAddr adr of
        CW -> return ()  -- send to best CW connection
        CCW -> return () -- send to best CCW connection

    Approx -> do
      let Just (Base64 adr) = a
      right <- head <$> gets cwConn
      left  <- head <$> gets ccwConn

      let dl = dist adr (remoteAddr  left)
      let dr = dist adr (remoteAddr right)
      let dm = dist adr myAddr

      when (dr < dm && dr < dl) $ return () -- send to best CW connection
      when (dl < dm && dl < dr) $ return () -- send to best CCW connection

-- Helper functions

withMVar :: MVar P2PState -> P2P () -> IO ()
withMVar m a = modifyMVar_ m $ \st -> do
  (res, s) <- runStateT (runErrorT a) st
  case res of
    Left e -> putStrLn e
    _      -> return ()
  return s
