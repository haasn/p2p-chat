import           Codec.Crypto.RSA (PublicKey)

import           Data.ByteString.Lazy (ByteString)
import qualified Data.Map as Map
import qualified Data.ByteString.Base64 as B64 (encode, decode)

-- Global monad

type P2P = StateT P2PState IO

-- Global state

data P2PState = P2PState
  { rightConn :: [Connection]
  , leftConn  :: [Connection]
  , keyTable  :: Map.Map Name Id
  , locTable  :: Map.Map Id Address
  , pubKey    :: PublicKey
  , privKey   :: PrivateKey
  }

-- Friendly types

type Id        = PublicKey
type Name      = String
type Signature = ByteString
type Address   = Double

-- Packet structure

data Packet = Packet RoutingHeader Content

type RoutingHeader = [RSection]
type Content       = [CSection]

-- Immediate data representation of all available sections, type and structure safe

data RSection =
    Target TargetType (Maybe Address)
  | Source Id (Base64 Signature)
  | SourceAddr Address (Base64 Signature)
  | Version Int
  | Support Int
  | Drop Address


data CSection =
    Message MessageType ByteString (Base64 Signature) -- This ByteString must be taken care of separately
  | Key (RSA64 Key) (Base64 Signature)

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

-- Safety types for Base64 and encryption; only used to enforce parsing/serializing rules

newtype Base64 t = Base64 t
newtype AES t    = AES t
newtype RSA t    = RSA t

-- Type class for serializing / deserializing

class Packet p where
  toPacket   :: p -> P2P ByteString
  fromPacket :: ByteString -> P2P p
