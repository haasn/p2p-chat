{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import           Prelude hiding (catch)

import           Codec.Crypto.RSA (generateKeyPair)

import           Control.Applicative
import           Control.Concurrent (forkIO)
import           Control.Concurrent.MVar hiding (withMVar)
import           Control.Exception hiding (handle)
import           Control.Monad.Error
import           Control.Monad.Reader (ask)
import           Control.Monad.RWS.Strict (execRWST)
import           Control.Monad.State.Strict

import           Crypto.Random (newGenIO, SystemRandom)

import           Data.ByteString (hGetLine)
import           Data.Char (toLower)
import qualified Data.Map as Map

import           GHC.IO.Handle hiding (hGetLine)

import           Network

import           System.Environment (getArgs)
import           System.Exit (ExitCode, exitSuccess)

import           P2P
import           P2P.Math
import           P2P.Parsing()
import           P2P.Processing
import           P2P.Queue
import           P2P.Sending
import           P2P.Serializing()
import           P2P.Types
import           P2P.Util

version :: String
version = "0.0"

defaultPort :: Port
defaultPort = 1027

-- Local meta-plumbing

data Meta = Meta
  { myMVar :: MVar P2PState
  , myPort  :: Port
  }

-- Initial state generation

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
    , dhtQueue  = []
    , pubKey    = pub
    , privKey   = priv
    , homeAddr  = 0.5
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

  -- Generate a new program state using this port as baseline
  state <- newState
  mvar  <- newMVar state
  let meta = Meta mvar port

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

    forkIO $ runThread h host meta `finally` runP2P meta (close h host)

  handleInput meta

-- Console input handler

handleInput :: Meta -> IO ()
handleInput m = forever . handle $ do
  line <- map toLower <$> getLine

  case line of
    "quit" -> exitSuccess
    "test.connect" -> connect m "localhost" defaultPort

    "test.global" -> runP2P m $
      sendGlobal [mkMessage MGlobal "Hello, world!"]

    "test.dump" -> runP2P m $
      get >>= throwError . show

    "test.queue" -> runP2P m $
      waitName "test" (sendAddr [mkMessage MGlobal "Foobar!"])

    _ -> putStrLn "[$] Unrecognized input"

connect :: Meta -> HostName -> Port -> IO ()
connect m host port = do
  h <- connectTo host (PortNumber port)
  putStrLn $ "[?] Connected to " ++ show host ++ ':': show port
  runP2P m $ do
    iam <- mkIAm <$> gets pubKey <*> gets homeAddr <*> ask
    hSend h $ Packet [Identify, iam] []
  forkIO $ runThread h host m `finally` runP2P m (close h host)
  return ()

runThread :: Handle -> HostName -> Meta -> IO ()
runThread h host m = do
  eof <- hIsEOF h
  unless eof $ do
   packet <- hGetLine h
   runP2P m (process h host packet >> prune)
   runThread h host m

-- Close a handle

close :: Handle -> HostName -> P2P ()
close h host = do
  liftIO $ hClose h
  liftIO . putStrLn $ "[?] Disconnected from " ++ show host
  delConnection h

-- Helper functions to synchronize threads using an MVar

withMVar :: Meta -> P2P () -> IO [(HostName, Port)]
withMVar m a = modifyMVar (myMVar m) $ \st -> do
  res <- runErrorT (execRWST a (myPort m) st)
  case res of
    Left e  -> do
      putStrLn $ "[!] " ++ e
      return (st, [])

    Right r -> return r

runP2P :: Meta -> P2P () -> IO ()
runP2P m a = withMVar m a >>= mapM_ (uncurry $ connect m)

-- Exception handler

handle :: IO () -> IO ()
handle a = a `catches`
  [ Handler $ \(e :: ExitCode)       -> throwIO e
  , Handler $ \(e :: AsyncException) -> throwIO e
  , Handler $ \(e :: SomeException)  -> putStrLn ("[*] " ++ show e)
  ]

-- Pretty outputting of program states, needed for ‘test.dump’

instance Show P2PState where
  show p = "P2PState:\n" ++
    "cwConn:\n" ++
    concatMap (showLine . showC) (cwConn p) ++

    "ccwConn:\n" ++
    concatMap (showLine . showC) (ccwConn p) ++

    "idTable:\n" ++
    concatMap (showLine . showIT) (Map.assocs $ idTable p) ++

    "locTable:\n" ++
    concatMap (showLine . showLT) (Map.assocs $ locTable p) ++

    "keyTable:\n" ++
    concatMap (showLine . showKT) (Map.assocs $ keyTable p) ++

    "pubKey: " ++ showId (pubKey p) ++ "\n" ++

    "homeAddr: " ++ show (homeAddr p) ++ "\n"

    where
      showLine :: String -> String
      showLine s = " - " ++ s ++ "\n"

      showC :: Connection -> String
      showC c =
        showId (remoteId c) ++ " @ " ++ show (remoteAddr c) ++
        " (" ++ hostName c ++ ":" ++ show (hostPort c) ++ ")"

      showIT :: (Name, Id) -> String
      showIT (name, id) = name ++ " -> " ++ showId id

      showLT :: (Id, Address) -> String
      showLT (id, adr) = showId id ++ " -> " ++ show adr

      showKT :: (Id, AESKey) -> String
      showKT (id, key) = showId id ++ " -> " ++ show key

      showId :: Id -> String
      showId id = '#' : show (hashId id)
