{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import           Prelude                  hiding (catch)

import           Codec.Crypto.RSA         (generateKeyPair)

import           Control.Applicative
import           Control.Concurrent       (forkIO)
import           Control.Concurrent.MVar  hiding (withMVar)
import           Control.Exception        hiding (handle)
import           Control.Monad.Error
import           Control.Monad.RWS.Strict (execRWST)
import           Control.Monad.State

import           Crypto.Random            (SystemRandom, newGenIO)

import           Data.ByteString          (hGetLine)
import           Data.Char                (toLower)
import qualified Data.Map                 as Map

import           GHC.IO.Handle            hiding (hGetLine)

import           Network

import           System.Exit              (ExitCode, exitSuccess)

import           P2P
import           P2P.Messaging
import           P2P.Options
import           P2P.Parsing              ()
import           P2P.Processing
import           P2P.Sending
import           P2P.Serializing          ()
import           P2P.Types
import           P2P.Util

-- Local meta-plumbing

data Meta = Meta
  { myMVar :: MVar P2PState
  , myOpts :: Options
  }

-- Initial state generation

newState :: IO P2PState
newState = do
  gen <- newGenIO :: IO SystemRandom
  let (pub, priv, newgen) = generateKeyPair gen 2048
  loop <- newEmptyMVar

  return P2PState
    { cwConn    = []
    , ccwConn   = []
    , idTable   = Map.empty
    , locTable  = Map.empty
    , keyTable  = Map.empty
    , chanList  = []
    , dhtQueue  = []
    , pubKey    = pub
    , privKey   = priv
    , homeAddr  = Nothing
    , randomGen = newgen
    , loopback  = loop
    , context   = nullContext
    }

-- Main action

main :: IO ()
main = withSocketsDo $ do

  -- Basic console output, for before an actual interface is implemented
  putStrLn $ "[?] p2p-chat v" ++ version ++ " loaded"
  putStrLn
    "[?] Legend: ? information, ~ warning, ! error, * exception, $ shell"

  -- Read arguments
  opts  <- getOptions

  -- Generate initial state and assign address for bootstrapping if needed
  state' <- newState
  let state = if bootstrap opts then state' { homeAddr = Just 0.5 } else state'

  -- Generate a new program state
  mvar <- newMVar state
  let meta = Meta mvar opts

  -- Open the listening socket
  sock  <- listenOn (PortNumber $ listenPort opts)

  -- Fork into the main listening thread
  forkIO $ (`finally` sClose sock) . forever . handle $ do
    (h, host, port) <- accept sock
    hSetBuffering h NoBuffering

    -- Debugging purposes
    putStrLn $ "[?] Accepted connection from " ++ show host ++ ':': show port

    forkIO $ runThread h host meta `finally` runP2P meta (close h host)
    return ()

  -- Spawn a loopback listener
  forkIO $ listenLoopback meta (loopback state)

  -- Connect if needed
  case connectAddr opts of
    Just (h, p) -> connect meta h p
    _ -> return ()

  handleInput meta

-- Console input handler

handleInput :: Meta -> IO ()
handleInput m = forever . handle $ do
  line <- map toLower <$> getLine

  case line of
    "quit" -> runP2P m (sendGlobal' [Quit] []) >> exitSuccess

    "test.connect" -> connect m "localhost" defaultPort

    "test.global" -> runP2P m $
      sendGlobal [mkGlobal "Hello, world!"]

    "test.dump" -> runP2P m $
      get >>= throwError . show

    "test.register" -> runP2P m $
      sendRegister "nand"

    "test.message" -> runP2P m $
      message "nand" "foo bar bat baz"

    "test.join" -> runP2P m $
      joinChannel "#foo"

    "test.channel" -> runP2P m $
      channel "#foo" "chan message"

    "test.invalid" -> runP2P m $
      channel "#invalid" "invalid message"

    "test.update" -> runP2P m sendUpdate

    _ -> putStrLn "[$] Unrecognized input"

-- Loopback listener

listenLoopback :: Meta -> MVar Packet -> IO ()
listenLoopback meta mvar = forever . handle $
  takeMVar mvar >>= runP2P meta . go

  where
    go :: Packet -> P2P ()
    go p = do
      resetContext
      setIsLoop
      parse p

-- Connect to a peer, for whatever purpose
-- Also sends IAM/IDENTIFY or DIALIN as needed

connect :: Meta -> HostName -> Port -> IO ()
connect m host port = do
  h <- connectTo host (PortNumber port)
  putStrLn $ "[?] Connected to " ++ show host ++ ':': show port
  runP2P m $ do
    addr <- gets homeAddr
    case addr of
      -- If we have an address, send IAM, IDENTIFY
      Just _  -> sendIdent h

      -- Otherwise, send a DIALIN
      Nothing -> hSend h $ Packet [DialIn] []

  forkIO $ runThread h host m `finally` runP2P m (close h host)
  return ()

connectSafe :: Meta -> HostName -> Port -> IO ()
connectSafe m host port = do
  skip <- hasConnection m host port
  unless skip $ connect m host port

hasConnection :: Meta -> HostName -> Port -> IO Bool
hasConnection m host port = do
  state <- readMVar (myMVar m)
  let conns = ccwConn state ++ cwConn state
  return $ any (\c -> hostName c == host && hostPort c == port) conns

-- Read/Process/Send loop, used for forkIO

runThread :: Handle -> HostName -> Meta -> IO ()
runThread h host m = do
  line <- hGetLine h
  -- liftIO $ print line
  handle . runP2P m $ process h host line >> prune

  -- Loop indefinitely
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
  res <- runErrorT (execRWST a (myOpts m) st)
  case res of
    Left e  -> do
      putStrLn $ "[!] " ++ e
      return (st, [])

    Right r -> return r

runP2P :: Meta -> P2P () -> IO ()
runP2P m a = withMVar m a >>= mapM_ (uncurry $ connectSafe m)

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
