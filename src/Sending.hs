module P2P.Sending where

import           Control.Applicative
import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (gets)
import           Control.Monad.Trans (liftIO)

import           Data.ByteString (ByteString, hPut)
import qualified Data.Map as Map

import           GHC.IO.Handle (Handle, hFlush, hPutChar)

import           P2P.Math
import           P2P.Serializing()
import           P2P.Types
import           P2P.Util

-- Send a packet

send :: Packet -> Connection -> P2P ()
send packet conn = encode packet >>= cSendRaw conn

hSend :: Handle -> Packet -> P2P ()
hSend h packet = encode packet >>= hSendRaw h

cSendRaw :: Connection -> ByteString -> P2P ()
cSendRaw = hSendRaw . socket

hSendRaw :: Handle -> ByteString -> P2P ()
hSendRaw h bs = do
  liftIO $ hPut h bs
  liftIO $ hPutChar h '\n'
  liftIO $ hFlush h

-- Special send functions

sendGlobal :: Content -> P2P ()
sendGlobal cs = do
  base <- makeHeader
  let rh = mkTarget TGlobal Nothing : base

  (head <$> gets cwConn) >>= send (Packet rh cs)

sendAddr :: Content -> Address -> P2P ()
sendAddr cs a = do
  base <- makeHeader
  home <- gets homeAddr
  let rh = mkTarget Exact (Just a) : base

  case dir home a of
    CW  -> (head <$> gets  cwConn) >>= send (Packet rh cs)
    CCW -> (head <$> gets ccwConn) >>= send (Packet rh cs)

sendHeader :: RoutingHeader -> Connection -> P2P ()
sendHeader rh conn = do
  base <- makeHeader
  send (Packet (rh ++ base) []) conn

sendDrop :: Address -> Connection -> P2P ()
sendDrop adr = sendHeader [mkDrop adr]

sendPanic :: Connection -> P2P ()
sendPanic = sendHeader [Panic]

-- Special context-dependent reply functions

reply :: Content -> P2P ()
reply cs = replyAddr >>= sendAddr cs

replyAddr :: P2P Address
replyAddr = do
  addr <- replyAddr'
  case addr of
    Nothing -> throwError "Trying to reply to unknown address"
    Just a  -> return a

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

  mapM_ (sendAddr cs) addrs

-- Helper function for generating header stubs

makeHeader :: P2P [RSection]
makeHeader = do
  id   <- gets pubKey
  addr <- gets homeAddr

  return
    [ mkSource id
    , mkSourceAddr addr
    , mkVersion 1
    , mkSupport 1
    ]
