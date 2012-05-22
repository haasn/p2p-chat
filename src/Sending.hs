module P2P.Sending where

import           Control.Applicative
import           Control.Concurrent.MVar (putMVar)
import           Control.Monad (unless)
import           Control.Monad.Error (throwError)
import           Control.Monad.State (gets)
import           Control.Monad.Trans (liftIO)

import           Data.ByteString (ByteString, hPut)
import qualified Data.Map as Map
import           Data.Maybe (fromJust, isJust)

import           GHC.IO.Handle (Handle, hFlush, hPutChar)

import           P2P.Math
import           P2P.Serializing()
import           P2P.Types
import           P2P.Util

-- Send a packet directly

hSendRaw :: Handle -> ByteString -> P2P ()
hSendRaw h bs = do
  liftIO $ hPut h bs
  liftIO $ hPutChar h '\n'
  liftIO $ hFlush h

hSend :: Handle -> Packet -> P2P ()
hSend h packet = encode packet >>= hSendRaw h

-- Functions for interacting directly with Connections

send :: Packet -> Connection -> P2P ()
send packet conn = encode packet >>= cSendRaw conn

cSendRaw :: Connection -> ByteString -> P2P ()
cSendRaw = hSendRaw . socket

sendHeader :: RoutingHeader -> Connection -> P2P ()
sendHeader rh conn = do
  base <- makeHeader
  send (Packet (rh ++ base) []) conn

-- Sending to the loopback connection

sendLoop :: Packet -> P2P ()
sendLoop p = do
  mvar <- gets loopback
  liftIO $ putMVar mvar p

-- Basic packet sending functions

sendGlobal' :: RoutingHeader -> Content -> P2P ()
sendGlobal' rh cs = do
  base <- makeHeader
  let rh' = mkTarget TGlobal Nothing : rh ++ base

  trySend CW (Packet rh' cs)

sendAddr :: TargetType -> RoutingHeader -> Content -> Address -> P2P ()
sendAddr tt rh cs a = do
  base <- makeHeader
  home <- gets homeAddr

  unless (isJust home) $ throwError "Cannot send a packet: No local address"

  let rh' = mkTarget tt (Just a) : rh ++ base

  trySend (dir (fromJust home) a) (Packet rh' cs)

trySend :: Direction -> Packet -> P2P ()
trySend d p = do
  f <- first d
  s <- second d
  let cs = f ++ reverse s

  case cs of
    x:_ -> send p x
    []  -> sendLoop p

  where
    first  CW = gets  cwConn
    first CCW = gets ccwConn

    second  CW = gets ccwConn
    second CCW = gets  cwConn

-- Higher order packet sending functions

sendDrop :: Address -> Address -> P2P ()
sendDrop adr = sendAddr Exact [mkDrop adr] []

sendWhoIs :: Name -> P2P ()
sendWhoIs name = sendApprox [mkWhoIs name] (hashName name)

sendWhereIs :: Id -> P2P ()
sendWhereIs id = sendApprox [mkWhereIs id] (hashId id)

sendRequest :: Connection -> P2P ()
sendRequest c = return () -- sendExact [Request] (remoteAddr c)

sendRegister :: Name -> P2P ()
sendRegister name = sendApprox [mkRegister name] (hashName name)

-- Special context-dependent reply functions

reply' :: RoutingHeader -> Content -> P2P ()
reply' rh cs = replyAddr >>= sendAddr Exact rh cs

replyAddr :: P2P Address
replyAddr = wrapError replyAddr' "Trying to reply to unknown address"

replyAddr' :: P2P (Maybe Address)
replyAddr' = do
  addr <- ctxAddr <$> gets context
  id   <- ctxId   <$> gets context

  case addr of
    Just _ -> return addr
    Nothing -> case id of
      Nothing -> return Nothing
      Just id -> Map.lookup id <$> gets locTable

replyMirror :: Content -> P2P ()
replyMirror cs = do
  -- Send to the remote client first
  reply cs

  -- Send to all of my peers next for mirroring
  conns <- (++) <$> gets cwConn <*> gets ccwConn
  let addrs = map remoteAddr conns

  mapM_ (sendExact cs) addrs

-- Less general alternatives for convenience

sendGlobal :: Content -> P2P ()
sendGlobal = sendGlobal' []

sendExact :: Content -> Address -> P2P ()
sendExact = sendAddr Exact []

sendApprox :: Content -> Address -> P2P ()
sendApprox = sendAddr Approx []

reply :: Content -> P2P ()
reply = reply' []

-- Helper function for generating header stubs

makeHeader :: P2P [RSection]
makeHeader = do
  id   <- gets pubKey
  addr <- gets homeAddr

  return $
    [ mkSource id ]
    ++
      case addr of
        Just a  -> [mkSourceAddr a]
        Nothing -> []
    ++
    [ mkVersion 1
    , mkSupport 1
    ]
