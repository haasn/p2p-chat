module P2P.Types where

import           Network (HostName)

import           Codec.Crypto.RSA (PublicKey(..), PrivateKey)

import           Crypto.Random (SystemRandom)

import           Control.Monad.State.Strict (StateT)
import           Control.Monad.Error (ErrorT)

import           Data.ByteString (ByteString)
import           Data.Map (Map)
import qualified Data.Map as Map

import           GHC.IO.Handle (Handle)

-- Global monad

type P2P = ErrorT String (StateT P2PState IO)

-- Global state

data P2PState = P2PState
  { cwConn    :: [Connection]
  , ccwConn   :: [Connection]
  , idTable   :: Map Name Id
  , locTable  :: Map Id Address
  , keyTable  :: Map Id AESKey
  , pubKey    :: PublicKey
  , privKey   :: PrivateKey
  , homeAddr  :: Address
  , randomGen :: SystemRandom
  , context   :: Context
  }

instance Show P2PState where
  show p = show (cwConn p, ccwConn p, idTable p, locTable p, keyTable p,
                 pubKey p, privKey p, homeAddr p, context p)

-- Friendly types

type Id         = PublicKey
type Name       = String
type Address    = Double
type AESKey     = ByteString

-- Connection type

data Connection = Connection
  { socket     :: Handle
  , remoteId   :: Id
  , remoteAddr :: Address
  , hostName   :: HostName
  }
 deriving (Show)

-- Packet structure

data Packet = Packet RoutingHeader Content deriving (Eq, Show)

type RoutingHeader = [RSection]
type Content       = [CSection]

-- Immediate data representation of all available sections,
-- type and structure safe

data RSection =
    Target TargetType (Maybe (Base64 Address))
  | Source (Base64 Id) Signature
  | SourceAddr (Base64 Address) Signature
  | Version (Base64 Integer)
  | Support (Base64 Integer)
  | Drop (Base64 Address)
  | Identify
  | IAm (Base64 Id) (Base64 Address)

  -- For parsing failures
  | RUnknown ByteString
 deriving (Eq, Show)

data CSection =
  -- This ByteString must be encoded separately
    Message MessageType ByteString Signature

  | Key (RSA64 AESKey) Signature

  -- Id table interactions

  | WhoIs (Base64 Name)
  | ThisIs (Base64 Name) (Base64 Id)
  | NoExist (Base64 Name)
  | Register (Base64 Name) Signature
  | Exist (Base64 Name)

  -- Location table interactions

  | WhereIs (Base64 Id)
  | HereIs (Base64 Id) (Base64 Address)
  | NotFound (Base64 Id)
  | Update (Base64 Address) Signature

  -- For parsing failures
  | CUnknown ByteString
 deriving (Eq, Show)

-- Helpers

type RSA64 t = Base64 (RSA t)
type AES64 t = Base64 (AES t)

-- Target types

data TargetType  = TGlobal | Exact | Approx deriving (Eq, Show, Read)
data MessageType = MGlobal | Channel | Single deriving (Eq, Show, Read)

-- Directional types for transfers

data Direction = CW | CCW deriving (Eq, Show, Read)

-- Safety type for Base64, only used to enforce parsing/serializing rules

newtype Base64 t = Base64 t deriving (Eq, Show)

-- Types for encryption, these are not decidable immediately

data AES t = AES t | UnAES ByteString deriving (Eq, Show)
data RSA t = RSA t | UnRSA ByteString deriving (Eq, Show)

-- Dummy type for an RSA signature, not checked immediately

data Signature = Signature | Verify ByteString ByteString
  deriving (Eq, Show, Read)

-- Type class for serializing / deserializing

class Serializable s where
  encode :: s -> P2P ByteString
  decode :: ByteString -> s

class Parsable s where
  parse :: s -> P2P ()

-- Serialization context, used to pass along key information

data Context = Context
  { ctxId      :: Maybe Id
  , ctxAddr    :: Maybe Address
  , ctxKey     :: Maybe AESKey
  , lastField  :: Maybe ByteString
  , ctxIsMe    :: Bool
  }
 deriving (Eq, Show)

-- Needed to derive Eq on PublicKey

instance Eq PublicKey where
  a == b = case a `compare` b of
    EQ -> True
    _  -> False

instance Ord PublicKey where
  compare (PublicKey a b c) (PublicKey a' b' c') =
    compare [fromIntegral a,b,c] [fromIntegral a',b',c']

-- Default context

nullContext :: Context
nullContext = Context Nothing Nothing Nothing Nothing False
