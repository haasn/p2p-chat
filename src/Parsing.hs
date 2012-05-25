{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
module P2P.Parsing where

import           Control.Applicative
import           Control.Monad (when, unless)
import           Control.Monad.Error (throwError)
import           Control.Monad.Reader (ask)
import           Control.Monad.State.Strict (gets)
import           Control.Monad.Trans (liftIO)
import           Control.Monad.Writer (tell)

import           Data.List (delete)
import           Data.Maybe (isJust, fromJust)

import           Network (HostName)

import           P2P
import           P2P.Crypto
import           P2P.Math
import           P2P.Queue
import           P2P.Sending
import           P2P.Types
import           P2P.Util

instance Parsable RSection where
  parse rsec = case rsec of
    Target tt ma -> do
      myAdr <- gets homeAddr

      -- Separate and decode the address
      Base64 adr <-
        if tt == TGlobal
          then return (Base64 0)
          else case ma of
            Nothing -> throwError "TargetType /= TGlobal and no target"
            Just m  -> return m

      case tt of
        TGlobal -> setIsMe

        Exact   -> when (myAdr == adr) setIsMe

        Approx  -> do
          next <- head <$> gets (case dir myAdr adr of
                                  CW  ->  cwConn
                                  CCW -> ccwConn)
          when (dist adr myAdr <= dist adr (remoteAddr next))
            setIsMe

    Source (Base64 id) s ->
      loadContext id >> parse s

    SourceAddr (Base64 addr) s ->
      parse s >> setContextAddr addr

    Version (Base64 ver) ->
      when (ver > 1) $
        throwError "Packet version unsupported, ignoring"

    Support (Base64 ver) ->
      when (ver < 1) $
        throwError "Client does not support minimum packet ver, dropping"

    Drop (Base64 addr) ->
      forgetAddr addr

    Quit -> do
      addr <- ctxAddr <$> gets context
      when (isJust addr) $ forgetAddr (fromJust addr)

      getContextId >>= forgetKey

    -- No-route sections

    Identify -> do
      h     <- fst <$> getContextHandle
      iam   <- mkIAm <$> gets pubKey <*> gets homeAddr <*> ask
      known <- safePeers

      hSend h $ Packet (iam : map (uncurry mkPeer) known) []

    Panic -> do
      h     <- fst <$> getContextHandle
      known <- safePeers
      hSend h $ Packet (map (uncurry mkPeer) known) []

    Peer (Base64 host) (Base64 port) -> do
      known <- peers
      unless ((host, port) `elem` known) $ tell [(host, port)]

    IAm (Base64 id) (Base64 adr) (Base64 port) -> do
      (h, host) <- getContextHandle
      addConnection h host port id adr

    RUnknown bs ->
      throwError $ "Unknown RSection: " ++ show bs

    where
      peers :: P2P [(HostName, Port)]
      peers = do
        conns <- (++) <$> gets cwConn <*> gets ccwConn
        let hosts = map hostName conns
        let ports = map hostPort conns
        return $ zip hosts ports

      -- Like peers but omits the peer's own address
      safePeers :: P2P [(HostName, Port)]
      safePeers = do
        unsafe <- peers
        conn   <- (fst <$> getContextHandle) >>= findConnection
        return $
          maybe unsafe (\c -> delete (hostName c, hostPort c) unsafe) conn

instance Parsable CSection where
  parse csec = case csec of
    Key (Base64 key) s -> do
      parse s
      id  <- getContextId
      key <- unRSA key
      insertKey id key

    WhoIs (Base64 name) -> do
      id <- getId name
      case id of
        Nothing -> reply [mkNoExist name]
        Just id -> reply [mkThisIs name id]

    ThisIs (Base64 name) (Base64 id) ->
      insertId name id >> hasId name

    Register (Base64 name) s -> do
      parse s
      id <- getContextId

      -- See if name exists
      id' <- getId name
      case id' of
        Nothing -> do
          insertId name id
          replyMirror [mkThisIs name id]
          hasId name
        Just _  -> reply [mkExist name]

    WhereIs (Base64 id) -> do
      adr <- getAddr id
      case adr of
        Nothing  -> reply [mkNotFound id]
        Just loc -> reply [mkHereIs id loc]

    HereIs (Base64 id) (Base64 addr) ->
      insertAddr id addr >> hasAddr id

    Update (Base64 addr) s -> do
      parse s
      id <- getContextId
      insertAddr id addr
      replyMirror [mkHereIs id addr]
      hasAddr id

    -- Failure messages

    NoExist (Base64 name) -> noId name >> liftIO (putStrLn $
      "[~] A DHT lookup for “" ++ name ++ "” failed with NOEXIST")

    NotFound (Base64 id) -> noAddr id >> liftIO (putStrLn $
      "[~] A DHT lookup for id “" ++ show id ++ "” failed with NOTFOUND")

    Exist (Base64 name) -> liftIO (putStrLn $
      "[~] Registration for “" ++ name ++ "” failed: Entry already exists")

    Message t m s -> do
      parse s
      case t of
        MGlobal ->
          let Base64 msg = decode m :: Base64 String
          in  liftIO $ putStrLn msg

        _       ->
          let Base64 msg = decode m :: Base64 (AES String)
          in  unAES msg >>= liftIO . putStrLn

    CUnknown bs ->
      throwError $ "Unknown CSection: " ++ show bs

-- Signature verification logic

instance Parsable Signature where
  parse Signature = return ()
  parse (Verify m s) = do
    let m' = decode m
    let (Base64 s') = decode s
    pk <- getContextId

    unless (verify pk m' s') $ throwError "Signature does not match id"

-- Full packet parsing

instance Parsable RoutingHeader where
  parse = mapM_ parse

instance Parsable Content where
  parse = mapM_ parse

instance Parsable Packet where
  parse (Packet rh cs) = do
    parse rh

    if isValid rh
      then do
        isme <- getIsMe
        when isme $ parse cs

      else unless (any isNoRoute rh) $
        throwError "Not a valid packet due to missing sections"


-- Helpers for encoding/decoding RSA and AES

unAES :: Serializable t => AES t -> P2P t
unAES (AES t)    = return t
unAES (UnAES bs) = decode .: decryptAES <$> getContextKey <*> pure bs

unRSA :: Serializable t => RSA t -> P2P t
unRSA (RSA t)    = return t
unRSA (UnRSA bs) = decode .: decryptRSA <$> gets privKey <*> pure bs
