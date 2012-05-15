module P2P.Processing where

import           Control.Applicative
import           Control.Monad.Error
import           Control.Monad.State.Strict

import           Data.ByteString (ByteString)
import           Data.List (find)

import           GHC.IO.Handle

import           Network

import           P2P
import           P2P.Math
import           P2P.Parsing()
import           P2P.Sending
import           P2P.Types

-- Process an incoming packet

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

    disconnect :: Connection -> P2P ()
    disconnect = liftIO . hClose . socket
