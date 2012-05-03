{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
module P2P.Parsing where

import           Control.Applicative
import           Control.Monad (join, when, unless)
import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (gets)
import           Control.Monad.Trans (liftIO)

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import qualified Data.Map as Map

import           P2P
import           P2P.Types
import           P2P.Util
import           P2P.Math
import           P2P.Sending

instance Parse RSection where
  parse (Target tt ma) = do
    -- Separate and decode the address
    Base64 adr <- if (tt == TGlobal)
      then return (Base64 0)
      else case ma of
        Nothing -> throwError "TargetType /= TGlobal and no target"
        Just m  -> return m

    case tt of
      TGlobal -> setIsMe
      Exact  -> do
        myadr <- gets homeAddr
        when (myadr == adr) setIsMe

      Approx -> do
        return ()
        -- TODO: Check neighbour distances and setIsMe here

  parse rsec = case rsec of
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

    IAm (Base64 id) (Base64 addr) -> do
      setContextId id
      setContextAddr addr
      insertAddr id addr

    -- This is handled separately since it isn't necessarily on a Connection
    Identify -> return ()

instance Parse CSection where
  parse csec = case csec of
    Key (Base64 key) s -> do
      parse s
      id  <- getContextId
      key <- unRSA key
      insertKey id key

    WhoIs (Base64 name) -> do
      idt <- gets idTable
      case Map.lookup name idt of
        Nothing -> reply [mkNoExist name]
        Just id -> reply [mkThisIs name id]

    ThisIs (Base64 name) (Base64 id) ->
      insertId name id

    -- TODO: Notify the user of these somehow
    NoExist _ -> return ()
    Exist   _ -> return ()

    Register (Base64 name) s -> do
      parse s
      id <- getContextId

      -- See if name exists
      idt <- gets idTable
      case Map.lookup name idt of
        Nothing -> do
          insertId name id
          reply [mkThisIs name id]
        Just _  -> reply [mkExist name]

    WhereIs (Base64 id) -> do
      loct <- gets locTable
      case Map.lookup id loct of
        Nothing  -> reply [mkNotFound id]
        Just loc -> reply [mkHereIs id loc]

    HereIs (Base64 id) (Base64 addr) ->
      insertAddr id addr

    Update (Base64 addr) s -> do
      parse s
      id <- getContextId
      insertAddr id addr

    Message t m s -> do
      parse s
      case t of
        MGlobal ->
          let Base64 msg = decode m :: Base64 String
          in  liftIO $ putStrLn msg

        _       ->
          let Base64 msg = decode m :: Base64 (AES String)
          in  unAES msg >>= liftIO . putStrLn

-- Signature verification logic

instance Parse Signature where
  parse Signature = return ()
  parse (Verify m s) = do
    let m' = decode m
    let (Base64 s') = decode s
    pk <- getContextId

    unless (verify' pk m' s') $ throwError "Signature does not match id"

-- Full packet parsing

instance Parse RoutingHeader where
  parse = mapM_ parse

instance Parse Content where
  parse = mapM_ parse

instance Parse Packet where
  parse (Packet rh cs) = do
    -- Make sure the context is always clean before parsing
    resetContext
    parse rh

    -- Check for presence of Source and Target, alternatively Identify or IAm
    if any isSource rh && any isTarget rh
       || any isIdentify rh || any isIAm rh
      then do
        isme <- getIsMe
        when isme $ parse cs

      else throwError
        "Source or Target not present and not a pre-route packet, ignoring"


-- Helpers for encoding/decoding RSA and AES

unAES :: Serializable t => AES t -> P2P t
unAES (AES t)    = return t
unAES (UnAES bs) = decode .: decryptAES <$> getContextKey <*> pure bs

unRSA :: Serializable t => RSA t -> P2P t
unRSA (RSA t)    = return t
unRSA (UnRSA bs) = decode .: decryptRSA <$> gets privKey <*> pure bs
