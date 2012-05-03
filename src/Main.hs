{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Prelude hiding (catch)

import Codec.Crypto.RSA (generateKeyPair)
import Crypto.Random (newGenIO, SystemRandom)

import Data.List (find)
import Data.ByteString (ByteString, hGetSome)
import Data.Char (toLower)
import qualified Data.Map as Map

import Control.Applicative
import Control.Monad.Error
import Control.Monad.State.Strict
import Control.Monad.Writer (runWriterT)
import Control.Exception hiding (handle)

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar hiding (withMVar)

import GHC.IO.Handle hiding (hGetLine)
import Network

import System.Exit (ExitCode, exitSuccess)
import System.Environment (getArgs)

import P2P
import P2P.Types
import P2P.Sending
import P2P.Serializing()
import P2P.Parsing()
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
    , randomGen = newgen
    , context   = nullContext
    }

defaultPort :: PortNumber
defaultPort = 1234

main :: IO ()
main = withSocketsDo $ do
  args  <- getArgs
  state <- newState
  mvar  <- newMVar state
  sock  <- let port = case args of
                        [p] -> fromIntegral $ read p
                        _   -> defaultPort
           in listenOn (PortNumber port)

  forkIO $ (`finally` sClose sock) . forever $ do
    (h, host, port) <- accept sock
    hSetBuffering h NoBuffering

    -- Debugging purposes
    putStrLn $ "[?] Accepted connection from " ++ show host ++ ':': show port

    forkIO $ runThread h host mvar `finally` withMVar mvar (close h host port)

  handleInput mvar

handleInput :: MVar P2PState -> IO ()
handleInput m = forever . handle $ do
  line <- map toLower <$> getLine

  case line of
    "quit" -> exitSuccess
    "test.connect" -> connect m defaultPort "localhost"

    "test.global" -> withMVar m $
      sendGlobal [mkMessage MGlobal "Hello, world!"]

    "test.dump" -> withMVar m $
      get >>= throwError . show

    _ -> putStrLn "[$] Unrecognized input"

connect :: MVar P2PState -> PortNumber -> HostName -> IO ()
connect mvar port host = do
  h <- connectTo host (PortNumber defaultPort)
  putStrLn $ "[?] Connected to " ++ show host ++ ':': show port
  withMVar mvar $ do
    iam <- mkIAm <$> gets pubKey <*> gets homeAddr
    hSend h $ Packet [Identify, iam] []
  forkIO $ runThread h host mvar `finally` withMVar mvar (close h host port)
  return ()

runThread :: Handle -> HostName -> MVar P2PState -> IO ()
runThread h host m = do
  eof <- hIsEOF h
  unless eof $ do
   -- FIXME: Make this not length dependent
   packet <- hGetSome h 2048
   withMVar m (process h host packet)
   runThread h host m

process :: Handle -> HostName -> ByteString -> P2P ()
process h host bs = do
  let p@(Packet rh _) = decode bs

  -- Parse right after decoding because sigs are verified here
  parse p

  -- Check for no route packets
  if any isNoRoute rh
    then mapM_ (preroute h host) rh
    else getConnection h >>= route bs p
 where
  getConnection :: Handle -> P2P Connection
  getConnection h = do
    conn <- findConnection h
    case conn of
      Nothing -> do
        hSend h $ Packet [Identify] []
        throwError "No Connection found, ignoring packet"
      Just c  -> return c

-- Close a handle

close :: Handle -> HostName -> PortNumber -> P2P ()
close h host port = do
  liftIO $ hClose h
  liftIO . putStrLn $ "[?] Disconnected from " ++ show host ++ ':': show port
  delConnection h

-- Evaluate a pre-Connection package

preroute :: Handle -> HostName -> RSection -> P2P ()
preroute h _ Identify = do
  myId   <- gets pubKey
  myAddr <- gets homeAddr
  hSend h $ Packet [mkIAm myId myAddr] []

preroute h host (IAm (Base64 id) (Base64 adr)) = addConnection h host id adr

-- Ignore everything else
preroute _ _ _ = return ()

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
    TGlobal ->
      unless (id == myId) $ do
        -- send to next CW connection
        conn <- head <$> gets cwConn
        cSendRaw conn bs

    -- TODO: Implement routing modes Exact and Approx

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

withMVar' :: MVar P2PState -> P2P () -> IO [HostName]
withMVar' m a = modifyMVar m $ \st -> do
  res <- runErrorT (runWriterT $ execStateT a st)
  case res of
    Left e  -> do
      putStrLn $ "[!] " ++ e
      return (st, [])

    Right r -> return r

withMVar :: MVar P2PState -> P2P () -> IO ()
withMVar m a = withMVar' m a >>= mapM_ (connect m defaultPort)

handle :: IO () -> IO ()
handle a = a `catches`
  [ Handler $ \(e :: ExitCode)       -> throwIO e
  , Handler $ \(e :: AsyncException) -> throwIO e
  , Handler $ \(e :: SomeException)  -> putStrLn ("[*] " ++ show e)
  ]
