module P2P.Types where

import           Codec.Crypto.RSA (PublicKey, PrivateKey)
import           Crypto.Random (SystemRandom)

import           Control.Monad.State.Strict (StateT)
import           Control.Monad.Error (ErrorT)

import           Data.ByteString (ByteString)
import qualified Data.Map as Map

-- Global monad

type P2P = ErrorT String (StateT P2PState IO)

-- Global state

data P2PState = P2PState
  { rightConn :: [Connection]
  , leftConn  :: [Connection]
  , keyTable  :: Map.Map Name Id
  , locTable  :: Map.Map Id Address
  , pubKey    :: PublicKey
  , privKey   :: PrivateKey
  , randomGen :: SystemRandom
  , context   :: Context
  }

-- Friendly types

type Id         = PublicKey
type Name       = String
type Signature  = ByteString
type Address    = Double
type Connection = ()
type AESKey     = ByteString

-- Packet structure

data Packet = Packet RoutingHeader Content

type RoutingHeader = [RSection]
type Content       = [CSection]

-- Immediate data representation of all available sections, type and structure safe

data RSection =
    Target TargetType (Maybe (Base64 Address))
  | Source (Base64 Id) (Base64 Signature)
  | SourceAddr (Base64 Address) (Base64 Signature)
  | Version (Base64 Integer)
  | Support (Base64 Integer)
  | Drop (Base64 Address)

data CSection =
    Message MessageType ByteString (Base64 Signature) -- This ByteString must be encoded separately
  | Key (RSA64 PublicKey) (Base64 Signature)

  -- Id table interactions

  | WhoIs (Base64 Name)
  | ThisIs (Base64 Name) (Base64 Id)
  | NoExist (Base64 Name)
  | Register (Base64 Name) (Base64 Signature)
  | Exist (Base64 Name)

  -- Location table interactions

  | WhereIs (Base64 Id)
  | HereIs (Base64 Id) (Base64 Address)
  | NotFound (Base64 Id)
  | Update (Base64 Address) (Base64 Signature)

-- Helpers

type RSA64 t = Base64 (RSA t)
type AES64 t = Base64 (AES t)

-- Target types

data TargetType  = TGlobal | Exact | Approx
data MessageType = MGlobal | Channel | Single

-- Safety types for Base64 and encryption; only used to enforce parsing/serializing rules

newtype Base64 t = Base64 t
newtype AES t    = AES t
newtype RSA t    = RSA t

-- Type class for serializing / deserializing

class Serializable s where
  encode :: s -> P2P ByteString
  decode :: ByteString -> P2P s

-- Serialization context, used to pass along key information

data Context = Context
  { keyRSA     :: Maybe PublicKey
  , keyAES     :: Maybe AESKey
  , targetId   :: Maybe Id
  , targetAddr :: Maybe Address
  }

-- Default context

nullContext :: Context
nullContext = Context Nothing Nothing Nothing Nothing
