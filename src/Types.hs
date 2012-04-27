module P2P.Types where

import           Codec.Crypto.RSA (PublicKey(..), PrivateKey)

import           Crypto.Random (SystemRandom)

import           Control.Monad.State.Strict (StateT)
import           Control.Monad.Error (ErrorT)

import           Data.ByteString (ByteString)
import qualified Data.Map as Map

-- Global monad

type P2P = ErrorT String (StateT P2PState IO)

-- Global state

data P2PState = P2PState
  { cwConn    :: [Connection]
  , ccwConn   :: [Connection]
  , keyTable  :: Map.Map Name Id
  , locTable  :: Map.Map Id Address
  , pubKey    :: PublicKey
  , privKey   :: PrivateKey
  , homeAddr  :: Address
  , randomGen :: SystemRandom
  , context   :: Context
  }

-- Friendly types

type Id         = PublicKey
type Name       = String
type Address    = Double
type AESKey     = ByteString

-- Connection type

data Connection = Connection
  { socket     :: ()
  , remoteAddr :: Address
  , remoteId   :: Id
  }

-- Packet structure

data Packet = Packet RoutingHeader Content deriving (Eq, Show)

type RoutingHeader = [RSection]
type Content       = [CSection]

-- Immediate data representation of all available sections, type and structure safe

data RSection =
    Target TargetType (Maybe (Base64 Address))
  | Source (Base64 Id) Signature
  | SourceAddr (Base64 Address) Signature
  | Version (Base64 Integer)
  | Support (Base64 Integer)
  | Drop (Base64 Address)
 deriving (Eq, Show)

data CSection =
    Message MessageType ByteString Signature -- This ByteString must be encoded separately
  | Key (RSA64 PublicKey) Signature

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
 deriving (Eq, Show)

-- Helpers

type RSA64 t = Base64 (RSA t)
type AES64 t = Base64 (AES t)

-- Target types

data TargetType  = TGlobal | Exact | Approx deriving (Eq, Show, Read)
data MessageType = MGlobal | Channel | Single deriving (Eq, Show, Read)

-- Directional types for transfers

data Direction = CW | CCW deriving (Eq, Show, Read)

-- Safety types for Base64 and encryption; only used to enforce parsing/serializing rules

newtype Base64 t = Base64 t deriving (Eq, Show)
newtype AES t    = AES t    deriving (Eq, Show)
newtype RSA t    = RSA t    deriving (Eq, Show)

-- Dummy type for an RSA signature

data Signature = Signature deriving (Eq, Show, Read)

-- Type class for serializing / deserializing

class Serializable s where
  encode :: s -> P2P ByteString
  decode :: ByteString -> P2P s

-- Serialization context, used to pass along key information

data Context = Context
  { targetId   :: Maybe Id
  , targetAddr :: Maybe Address
  , targetKey  :: Maybe AESKey
  , lastField  :: Maybe ByteString
  }
 deriving (Eq, Show)

-- Needed to derive Eq on PublicKey

instance Eq PublicKey where
  (PublicKey a b c) == (PublicKey a' b' c') =
    (a == a') && (b == b') && (c == c')

-- Default context

nullContext :: Context
nullContext = Context Nothing Nothing Nothing Nothing
