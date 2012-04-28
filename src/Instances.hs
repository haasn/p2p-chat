{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}

module P2P.Instances where

import           Control.Monad (join, when, unless)
import           Control.Monad.Error (throwError)
import           Control.Monad.State.Strict (get, gets, modify)
import           Control.Monad.Trans (liftIO)
import           Control.Applicative

import           Codec.Crypto.RSA (PublicKey(..))

import           Data.ByteString (ByteString, hPut)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64 (encode, decode)

import           Data.String (fromString)
import           Data.Char (toLower)

import qualified Data.Map as Map

import           Data.Text (Text, unpack)
import           Data.Text.Encoding

import           GHC.IO.Handle (Handle, hFlush)

import           P2P
import           P2P.Types
import           P2P.Util

-- Section logic

instance Serializable RSection where
  encode (Target     t a) = sec "TARGET"     [encode t, encode a]
  encode (Source     i _) = sec "SOURCE"     [encode i, sign]
  encode (SourceAddr a _) = sec "SOURCEADDR" [encode a, sign]
  encode (Version    v  ) = sec "VERSION"    [encode v]
  encode (Support    v  ) = sec "SUPPORT"    [encode v]
  encode (Drop       a  ) = sec "DROP"       [encode a]
  encode (IAm        i a) = sec "IAM"        [encode i, encode a]
  encode (Identify      ) = sec "IDENTIFY"   []

  decode bs = do
    res <- parse bs
    case res of
      ("target", tt:l) -> do
        tt' <- decode tt
        case tt' of
          TGlobal -> setIsMe >> return (Target TGlobal Nothing)
          t       -> Target t <$> decode (head l)
          -- FIXME: Check and set ctxIsMe

      ("source", [i,s]) -> do
        s <- verify i s
        i@(Base64 id) <- decode i
        loadContext id
        return $ Source i s

      ("sourceaddr", [a,s]) -> do
        s <- verify a s
        a@(Base64 addr) <- decode a
        setContextAddr addr
        return $ SourceAddr a s

      ("version", [v]) -> do
        v@(Base64 ver) <- decode v
        when (ver > 1) $ throwError "Packet version unsupported, ignoring"
        return $ Version v

      ("support", [v]) -> do
        v@(Base64 ver) <- decode v
        when (ver < 1) $ throwError "Client does not support minimum packet ver, dropping"
        return $ Support v

      ("drop", [a]) -> do
        a@(Base64 addr) <- decode a
        forgetAddr addr
        return $ Drop a

      ("iam", [i,a]) -> do
        i@(Base64 id)   <- decode i
        a@(Base64 addr) <- decode a
        setContextId id
        setContextAddr addr
        insertAddr id addr
        return $ IAm i a

      -- This is processed separately
      ("identify", []) -> return Identify

      -- Test “functions” for debugging
      ("test.dump", []) -> do
        get >>= throwError . show

      ("test.global", []) -> do
        sendGlobal [mkMessage MGlobal "Hello, world!"]
        throwError "test.global"

      _ -> throwError "RSection failed to parse"

instance Serializable CSection where
  encode (Message t m s) = sec "MESSAGE" [encode t, m', sign]
    where m' = case t of
            MGlobal -> encode $ Base64 m
            _       -> encode $ Base64 (AES m)

  encode (Key      p _) = sec "KEY"      [encode p, sign]
  encode (WhoIs      n) = sec "WHOIS"    [encode n]
  encode (ThisIs   n i) = sec "THISIS"   [encode n, encode i]
  encode (NoExist    n) = sec "NOEXIST"  [encode n]
  encode (Register n _) = sec "REGISTER" [encode n, sign]
  encode (Exist      n) = sec "EXIST"    [encode n]
  encode (WhereIs    i) = sec "WHEREIS"  [encode i]
  encode (HereIs   i a) = sec "HEREIS"   [encode i, encode a]
  encode (NotFound   i) = sec "NOTFOUND" [encode i]
  encode (Update   a _) = sec "UPDATE"   [encode a, sign]

  decode bs = do
    res <- parse bs
    case res of
      ("key", [k,s]) -> do
        s <- verify k s
        k@(Base64 (RSA key)) <- decode k
        id <- getContextId
        insertKey id key
        return $ Key k s

      -- ID table interactions

      ("whois", [n]) -> do
        n@(Base64 name) <- decode n
        idt <- gets idTable
        case Map.lookup name idt of
          Nothing -> return () -- TODO: Reply with NOEXIST
          Just id -> return () -- TODO: Reply with THISIS
        return $ WhoIs n

      ("thisis", [n,i]) -> do
        n@(Base64 name) <- decode n
        i@(Base64 id)   <- decode i
        insertId name id
        return $ ThisIs n i

      ("noexist", [n]) -> NoExist  <$> decode n

      ("register", [n,s]) -> do
        s <- verify n s
        n@(Base64 name) <- decode n
        id <- getContextId

        -- See if name exists
        idt <- gets idTable
        case Map.lookup name idt of
          Nothing -> insertId name id -- TODO: Reply with THISIS
          Just _  -> return () -- TODO: Reply with EXIST
        return $ Register n s

      ("exist", [n]) -> Exist <$> decode n

      -- Location table interactions

      ("whereis", [i]) -> do
        i@(Base64 id) <- decode i
        loct <- gets locTable
        case Map.lookup id loct of
          Nothing -> return ()  -- TODO: Reply with NOTFOUND
          Just loc -> return () -- TODO: Reply with HEREIS
        return $ WhereIs i

      ("hereis", [i,a]) -> do
        i@(Base64 id)   <- decode i
        a@(Base64 addr) <- decode a
        insertAddr id addr
        return $ HereIs i a

      ("notfound", [i]) -> NotFound <$> decode i

      ("update", [a,s]) -> do
        s <- verify a s
        a@(Base64 addr) <- decode a
        id <- getContextId
        insertAddr id addr
        return $ Update a s

      ("message" , [t,m,s]) -> do
        s  <- verify m s
        t <- decode t
        case t of
          MGlobal -> do
            m@(Base64 msg) <- decode m
            liftIO $ putStrLn msg

          _       -> do
            m@(Base64 (AES msg)) <- decode m
            liftIO $ putStrLn msg
        return $ Message t m s

      _ -> throwError "CSection failed to parse"

-- Trivial data types

instance Serializable ByteString where
  encode = return
  decode = return

instance Serializable Text where
  encode = return . encodeUtf8
  decode = fromEither' . decodeUtf8'

instance Serializable String where
  encode   = encode . (fromString :: String -> Text)
  decode b = unpack <$> decode b

instance Serializable Integer where
  encode = return . encIntegral
  decode = return . decIntegral

instance Serializable Double where
  encode = return . encDouble
  decode = return . decDouble

instance Serializable TargetType where
  encode TGlobal = encode "GLOBAL"
  encode Exact   = encode "EXACT"
  encode Approx  = encode "APPROX"

  decode bs = read' <$> decode bs
    where
      read' s = case map toLower s of
        "global" -> TGlobal
        "exact"  -> Exact
        "approx" -> Approx

instance Serializable MessageType where
  encode MGlobal = encode "GLOBAL"
  encode Channel = encode "CHANNEL"
  encode Single  = encode "SINGLE"

  decode bs = read' <$> decode bs
    where
      read' s = case map toLower s of
        "global"  -> MGlobal
        "channel" -> Channel
        "single"  -> Single

instance Serializable s => Serializable (Maybe s) where
  encode Nothing  = return BS.empty
  encode (Just s) = encode s

  decode bs = if BS.length bs == 0
    then return Nothing
    else Just <$> decode bs

instance Serializable PublicKey where
  encode (PublicKey s n e) = return $ BS.concat [encIntegral s, encIntegral n, encIntegral e]

  decode bs = return $ PublicKey size (decIntegral n) (decIntegral e)
    where
      (s,rest) = BS.splitAt 2 bs
      size     = decIntegral s
      (n,e)    = BS.splitAt (fromIntegral size) rest

-- Base64 and encryption logic

instance Serializable s => Serializable (Base64 s) where
  encode (Base64 s) = B64.encode <$> encode s
  decode bs         = Base64 <$> (decode =<< fromEither (B64.decode bs))

instance Serializable s => Serializable (RSA s) where
  encode (RSA s) = join $ encryptRSA <$> getContextId <*> encode s

  decode bs = do
    key <- gets privKey
    RSA <$> decode (decryptRSA key bs)

instance Serializable s => Serializable (AES s) where
  encode (AES s) = join $ encryptAES <$> getContextKey <*> encode s

  decode bs = do
    key <- getContextKey
    AES <$> decode (decryptAES key bs)

-- Parameter grouping logic

group' :: [P2P ByteString] -> P2P ByteString
group' l = (BS.intercalate (pack' " ") . filter (not . BS.null)) <$> mapM upd l
  where
    upd :: P2P ByteString -> P2P ByteString
    upd a = do
      res <- a
      setLastField res
      return res

ungroup' :: ByteString -> [ByteString]
ungroup' = BS.split $ ord' ' '

sec :: String -> [P2P ByteString] -> P2P ByteString
sec c l = group' $ encode c : l

parse' :: [ByteString] -> P2P (String, [ByteString])
parse' []     = throwError "Empty section!"
parse' (x:xs) = do
  cmd <- map toLower <$> decode x
  return (cmd, xs)

parse :: ByteString -> P2P (String, [ByteString])
parse = parse' . ungroup'

-- Section grouping logic

instance Serializable RoutingHeader where
  encode rh = BS.intercalate (pack' "\n") <$> mapM encode rh
  decode bs = mapM decode $ BS.split (ord' '\n') bs

instance Serializable Content where
  encode rh = BS.intercalate (pack' "\n") <$> mapM encode rh
  decode bs = mapM decode $ BS.split (ord' '\n') bs

instance Serializable Packet where
  encode (Packet rh c) = BS.concat <$> sequence [encode rh, return $ pack' "\n\n", encode c]
  decode bs = do
    let (rh, c) = BS.breakSubstring (pack' "\n\n") bs
    -- Make sure the context is always clean before decoding
    resetContext
    header <- decode rh
    -- Check for presence of Source and Target, alternatively Identify or IAm
    if any isSource header && any isTarget header || any isIdentify header || any isIAm header
      then do
        isme <- getIsMe
        if isme
          then Packet <$> pure header <*> decode (BS.drop 2 c) -- drop the \n\n too
          else return $ Packet header []
      else throwError "Source or Target not present and not a pre-route packet, ignoring"

-- Helper functions for RSA serialization

sign :: P2P ByteString
sign = (Base64 .: sign' <$> gets privKey <*> getLastField) >>= encode

verify :: ByteString -> ByteString -> P2P Signature
verify m s = do
  m' <- decode m
  (Base64 s') <- decode s
  pk <- getContextId

  if verify' pk m' s'
    then return Signature
    else throwError "Signature does not match id"

-- Send a packet

cSend :: Connection -> Packet -> P2P ()
cSend conn packet = encode packet >>= cSendRaw conn

hSend :: Handle -> Packet -> P2P ()
hSend h packet = encode packet >>= hSendRaw h

cSendRaw :: Connection -> ByteString -> P2P ()
cSendRaw = hSendRaw . socket

hSendRaw :: Handle -> ByteString -> P2P ()
hSendRaw h bs = do
  liftIO $ hPut h bs
  liftIO $ hFlush h

sendGlobal :: [CSection] -> P2P ()
sendGlobal cs = do
  next <- head <$> gets cwConn
  base <- makeHeader
  let rh = mkTarget TGlobal Nothing : base

  cSend next (Packet rh cs)

makeHeader :: P2P [RSection]
makeHeader = do
  id   <- gets pubKey
  addr <- gets homeAddr

  return $
    [ mkSource id
    , mkSourceAddr addr
    , mkVersion 1
    , mkSupport 1
    ]
