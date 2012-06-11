{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
module P2P.Parsing where

import           Control.Applicative
import           Control.Monad (when, unless)
import           Control.Monad.Error (throwError)
import           Control.Monad.Reader (asks)
import           Control.Monad.State (gets, modify)
import           Control.Monad.Trans (liftIO)
import           Control.Monad.Writer (tell)

import           Data.Maybe (isJust, fromJust)

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
      myAdr' <- gets homeAddr

      unless (isJust myAdr') $ throwError
        "Trying to parse a routed packet before client has an assigned address."

      let Just myAdr = myAdr'

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
          nexts <- gets (case dir myAdr adr of
                           CW  ->  cwConn
                           CCW -> ccwConn)
          case nexts of
            []     -> setIsMe
            next:_ -> when (dist adr myAdr <= dist adr (remoteAddr next))
                        setIsMe

    Source (Base64 id) s (Base64 addr) s' -> do
      -- Here the parse happens afterwards because we can't verify anything
      -- without knowing the ID
      loadContext id
      parse s

      parse s'
      setContextAddr addr

      -- Add the address to the DHT for future purposes
      insertAddr id addr
      hasAddr id

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
      h <- fst <$> getContextHandle
      Just addr <- gets homeAddr

      iam <- mkIAm <$> gets pubKey <*> pure addr <*> asks listenPort
      hSend h $ Packet [iam] []

    IAm (Base64 id) (Base64 adr) (Base64 port) -> do
      (h, host) <- getContextHandle
      insertAddr id adr
      addConnection h host port id adr

    DialIn -> do
      (h, _) <- getContextHandle

      withPeers $ \peers -> do
        hSend h $ let
          addrs = map (\(_,_,a) -> a) peers
          addr  = makeUnique addrs
          in Packet [mkOffer addr] (map (uncurry3 mkPeer) peers)

        loop <- getIsLoop
        src  <- ctxId <$> gets context
        myId <- gets pubKey

        when (loop || src == Just myId) $ sendIdent h

      -- Send off a random REQUEST now that we've queued up the withPeers
      genAddress >>= sendApprox [Request]

    Offer (Base64 addr) -> do
      modify $ \st -> st { homeAddr = Just addr }

      ctxHasPeers
      withPeers $ tell . map (\(a,b,_) -> (a,b))

    RUnknown bs ->
      throwError $ "Unknown or malformed RSection: " ++ show bs

instance Parsable CSection where
  parse csec = case csec of
    Global (Base64 msg) s -> do
      parse s
      liftIO . putStrLn $ "<GLOBAL> " ++ msg

    Channel (Base64 raw) s -> do
      parse s
      msg <- unAES raw
      liftIO . putStrLn $ "<CHANNEL> " ++ msg

    Single (Base64 raw) s -> do
      parse s
      msg <- unAES raw
      liftIO . putStrLn $ "<SINGLE> " ++ msg

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

    Request -> do
      known <- knownPeers
      reply $ Response : map (uncurry3 mkPeer) known

    Response -> do
      -- Unknown if this is a bug or not, need larger debugging.
      ctxHasPeers

      loop <- getIsLoop
      unless loop $ do
        Just c <- (fst <$> getContextHandle) >>= findConnection
        ctxAddPeer (hostName c, hostPort c, remoteAddr c)

    Peer (Base64 host) (Base64 port) (Base64 addr) ->
      -- This is handled separately in Packet's parse because of the involvement
      -- of a bootstrapping queue, so just pass it into the context.
      ctxAddPeer (host, port, addr)

    -- Failure messages

    NoExist (Base64 name) -> noId name >> liftIO (putStrLn $
      "[~] A DHT lookup for “" ++ name ++ "” failed with NOEXIST")

    NotFound (Base64 id) -> noAddr id >> liftIO (putStrLn $
      "[~] A DHT lookup for id “" ++ show id ++ "” failed with NOTFOUND")

    Exist (Base64 name) -> liftIO (putStrLn $
      "[~] Registration for “" ++ name ++ "” failed: Entry already exists")

    CUnknown bs ->
      throwError $ "Unknown or malformed CSection: " ++ show bs

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
    let noRoute = any isNoRoute rh

    if isValid rh
      then do
        isme <- getIsMe
        when isme $ parse cs

      else if noRoute
        then parse cs
        else throwError "Not a valid packet due to missing sections"

    -- Check for PEERs and handle as needed
    peers <- ctxPeers <$> gets context
    when (isJust peers) $ hasPeers (fromJust peers)

-- Helpers for encoding/decoding RSA and AES

unAES :: Serializable t => AES t -> P2P t
unAES (AES t)    = return t
unAES (UnAES bs) = decode .: decryptAES <$> getContextKey <*> pure bs

unRSA :: Serializable t => RSA t -> P2P t
unRSA (RSA t)    = return t
unRSA (UnRSA bs) = decode .: decryptRSA <$> gets privKey <*> pure bs
