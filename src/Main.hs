{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import           Prelude hiding (catch)

import           Codec.Crypto.RSA (generateKeyPair)

import           Control.Applicative
import           Control.Concurrent (forkIO)
import           Control.Concurrent.MVar hiding (withMVar)
import           Control.Exception hiding (handle)
import           Control.Monad.Error
import           Control.Monad.State.Strict
import           Control.Monad.Writer (runWriterT)

import           Crypto.Random (newGenIO, SystemRandom)

import           Data.ByteString (hGetLine)
import           Data.Char (toLower)
import qualified Data.Map as Map

import           GHC.IO.Handle hiding (hGetLine)

import           Network

import           System.Environment (getArgs)
import           System.Exit (ExitCode, exitSuccess)

import           P2P
import           P2P.Parsing()
import           P2P.Processing
import           P2P.Sending
import           P2P.Serializing()
import           P2P.Types
import           P2P.Util

version :: String
version = "0.0"

defaultPort :: Port
defaultPort = 1027

-- Initial state generation

newState :: Port -> IO P2PState
newState port = do
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
    , homePort  = port
    , randomGen = newgen
    , context   = nullContext
    }

-- Main action

main :: IO ()
main = withSocketsDo $ do
  -- Read arguments and process port number if present
  args  <- getArgs
  let { port = case args of
    [p] -> fromIntegral $ read p
    _   -> defaultPort
  }

  -- Generate a new program state using this port as baselin
  state <- newState port
  mvar  <- newMVar state

  -- Open the listening socket
  sock  <- listenOn (PortNumber port)

  -- Basic console output, for before an actual interface is implemented
  putStrLn $ "[?] p2p-chat v" ++ version ++ " loaded"
  putStrLn
    "[?] Legend: ? information, ~ warning, ! error, * exception, $ shell"

  -- Fork into the main listening thread
  forkIO $ (`finally` sClose sock) . forever $ do
    (h, host, port) <- accept sock
    hSetBuffering h NoBuffering

    -- Debugging purposes
    putStrLn $ "[?] Accepted connection from " ++ show host ++ ':': show port

    forkIO $ runThread h host mvar `finally` withMVar mvar (close h host)

  handleInput mvar

-- Console input handler

handleInput :: MVar P2PState -> IO ()
handleInput m = forever . handle $ do
  line <- map toLower <$> getLine

  case line of
    "quit" -> exitSuccess
    "test.connect" -> connect m "localhost" defaultPort

    "test.global" -> withMVar m $
      sendGlobal [mkMessage MGlobal "Hello, world!"]

    "test.dump" -> withMVar m $
      get >>= throwError . show

    _ -> putStrLn "[$] Unrecognized input"

connect :: MVar P2PState -> HostName -> Port -> IO ()
connect mvar host port = do
  h <- connectTo host (PortNumber port)
  putStrLn $ "[?] Connected to " ++ show host ++ ':': show port
  withMVar mvar $ do
    iam <- mkIAm <$> gets pubKey <*> gets homeAddr <*> gets homePort
    hSend h $ Packet [Identify, iam] []
  forkIO $ runThread h host mvar `finally` withMVar mvar (close h host)
  return ()

runThread :: Handle -> HostName -> MVar P2PState -> IO ()
runThread h host m = do
  eof <- hIsEOF h
  unless eof $ do
   packet <- hGetLine h
   withMVar m (process h host packet >> prune)
   runThread h host m

-- Close a handle

close :: Handle -> HostName -> P2P ()
close h host = do
  liftIO $ hClose h
  liftIO . putStrLn $ "[?] Disconnected from " ++ show host
  delConnection h

-- Helper functions to synchronize threads using an MVar

withMVar' :: MVar P2PState -> P2P () -> IO [(HostName, Port)]
withMVar' m a = modifyMVar m $ \st -> do
  res <- runErrorT (runWriterT $ execStateT a st)
  case res of
    Left e  -> do
      putStrLn $ "[!] " ++ e
      return (st, [])

    Right r -> return r

withMVar :: MVar P2PState -> P2P () -> IO ()
withMVar m a = withMVar' m a >>= mapM_ (uncurry $ connect m)

-- Exception handler

handle :: IO () -> IO ()
handle a = a `catches`
  [ Handler $ \(e :: ExitCode)       -> throwIO e
  , Handler $ \(e :: AsyncException) -> throwIO e
  , Handler $ \(e :: SomeException)  -> putStrLn ("[*] " ++ show e)
  ]
