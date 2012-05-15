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

import           Data.ByteString (ByteString, hGetLine)
import           Data.Char (toLower)
import           Data.List (find)
import qualified Data.Map as Map

import           GHC.IO.Handle hiding (hGetLine)

import           Network

import           System.Environment (getArgs)
import           System.Exit (ExitCode, exitSuccess)

import           P2P
import           P2P.Math
import           P2P.Parsing()
import           P2P.Sending
import           P2P.Serializing()
import           P2P.Types
import           P2P.Util

version :: String
version = "0.0"

defaultPort :: PortNumber
defaultPort = 1027

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

main :: IO ()
main = withSocketsDo $ do
  args  <- getArgs
  state <- newState
  mvar  <- newMVar state
  sock  <- let port = case args of
                        [p] -> fromIntegral $ read p
                        _   -> defaultPort
           in listenOn (PortNumber port)

  putStrLn $ "[?] p2p-chat v" ++ version ++ " loaded"
  putStrLn
    "[?] Legend: ? information, ~ warning, ! error, * exception, $ shell"

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

disconnect :: Connection -> P2P ()
disconnect = liftIO . hClose . socket

runThread :: Handle -> HostName -> MVar P2PState -> IO ()
runThread h host m = do
  eof <- hIsEOF h
  unless eof $ do
   packet <- hGetLine h
   withMVar m (process h host packet >> prune)
   runThread h host m

process :: Handle -> HostName -> ByteString -> P2P ()
process h host bs = do
  let p@(Packet rh _) = decode bs

  resetContext
  setContextHandle (h, host)

  parse p

  -- Check for no route packets
  unless (any isNoRoute rh) $ getConnection h >>= route bs p

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

-- Route a packet

route :: ByteString -> Packet -> Connection -> P2P ()
route bs (Packet rh _) conn = do
  myId   <- gets pubKey
  myAddr <- gets homeAddr
  isMe <- getIsMe

  let Just (Source (Base64 id) _) = find isSource rh
  let Just (Target tt a) = find isTarget rh

  case tt of
    TGlobal ->
      unless (id == myId) $ do
        -- Send to next CW connection
        conn <- head <$> gets cwConn
        cSendRaw conn bs

    Exact -> let
        -- Local name for the address, pattern matched to remove type clutter
        Just (Base64 adr) = a

        -- The Exact mode routing function, defined here since it references
        -- the local names adr and d
        sendExact :: [Connection] -> P2P ()
        sendExact [] = throwError $
          "Failed sending packet " ++ show d ++ ": no connections"

        sendExact [last] = cSendRaw last bs

        sendExact (c:cs) = let rAdr = remoteAddr c in
          -- Check for an exact match
          if adr == rAdr
          then cSendRaw c bs

          -- Otherwise, check to see if the direction is still the same
          else if d == dir rAdr adr
            -- Recurse if it is, last case is handled separately
            then sendExact cs

            -- DROP if it isn't, implying a left-out address.
            else sendDrop adr conn

        -- Local name for the address from us to the target
        d = dir myAddr adr

      in
        unless isMe $ getsDir d >>= sendExact

    Approx -> do
      let Just (Base64 adr) = a
      unless isMe $ head <$> getsDir (dir myAddr adr) >>= (`cSendRaw` bs)

-- Check the connection buffer sizes and prune or panic

prune :: P2P ()
prune = updateCW checkConns >> updateCCW checkConns
  where
    checkConns :: [Connection] -> P2P [Connection]
    checkConns cs
      | len >  5  = mapM_ disconnect rest >> return keep
      | len == 0  = liftIO (putStrLn "[~] Empty connection buffer!") >> return cs
      | len <  3  = sendPanic (head cs) >> return cs
      | otherwise = return cs
        where
          len = length cs
          (keep, rest) = splitAt 5 cs

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
