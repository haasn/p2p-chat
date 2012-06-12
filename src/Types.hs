module P2P.Types where

import           Control.Concurrent.MVar (MVar)
import           Control.Monad.Error (ErrorT)
import           Control.Monad.RWS.Strict (RWST)

import           Crypto.Random (SystemRandom)
import           Crypto.Types.PubKey.RSA (PublicKey(..), PrivateKey)

import           Data.ByteString (ByteString)
import           Data.Map (Map)

import           GHC.IO.Handle (Handle)

import           Network (HostName, PortNumber)

-- Global monad

type P2P = RWST Options [(HostName, Port)] P2PState (ErrorT String IO)

-- Global state

data P2PState = P2PState
  { cwConn    :: [Connection]
  , ccwConn   :: [Connection]
  , idTable   :: Map Name Id
  , locTable  :: Map Id Address
  , keyTable  :: Map Id AESKey
  , chanList  :: [String]
  , dhtQueue  :: Queue
  , pubKey    :: PublicKey
  , privKey   :: PrivateKey
  , homeAddr  :: Maybe Address
  , randomGen :: SystemRandom
  , loopback  :: MVar Packet
  , context   :: Context
  }

-- Friendly type synonyms

type Id         = PublicKey
type Name       = String
type Address    = Double
type AESKey     = ByteString
type Port       = PortNumber
type Queue      = [Delayed]

-- Version and port globals

version :: String
version = "0.0"

defaultPort :: Port
defaultPort = 1027

-- Connection type

data Connection = Connection
  { socket     :: Handle
  , remoteId   :: Id
  , remoteAddr :: Address
  , hostName   :: HostName
  , hostPort   :: Port
  }
 deriving (Show)

-- Packet structure

data Packet = Packet RoutingHeader Content deriving (Eq, Show)

type RoutingHeader = [RSection]
type Content       = [CSection]

-- Immediate data representation of all available sections,
-- type and structure safe

data RSection
  = Target TargetType (Maybe (Base64 Address))
  | Source (Base64 Id) Signature (Base64 Address) Signature
  | Version (Base64 Integer)
  | Support (Base64 Integer)
  | Drop (Base64 Address)
  | Quit

  -- No-route sections
  | Identify
  | IAm (Base64 Id) (Base64 Address) (Base64 Port)
  | DialIn
  | Offer (Base64 Address)

  -- For parsing failures
  | RUnknown ByteString
 deriving (Eq, Show)

data CSection
  -- The three types of message
  = Global (Base64 String) Signature
  | Channel (AES64 String) Signature
  | Single (AES64 String) Signature

  -- Key negotiation
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

  -- Dial-in and recovery

  | Request
  | Response
  | Peer (Base64 HostName) (Base64 Port) (Base64 Address)

  -- For parsing failures
  | CUnknown ByteString
 deriving (Eq, Show)

-- Helpers

type RSA64 t = Base64 (RSA t)
type AES64 t = Base64 (AES t)

-- Target types

data TargetType  = TGlobal | Exact | Approx deriving (Eq, Show, Read)

-- Represents a delayed delivery packet, for when addresses are not known

data Delayed
  = NeedId Name (Id -> P2P ())
  | NeedAddr Id (Address -> P2P ())
  | NeedPeers ([(HostName, Port, Address)] -> P2P ())

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
  , ctxHandle  :: Maybe (Handle, HostName)
  , ctxPeers   :: Maybe [(HostName, Port, Address)]
  , ctxIsMe    :: Bool
  , ctxIsLoop  :: Bool
  }
 deriving (Eq, Show)

-- Needed for using publickeys as map keys

instance Ord PublicKey where
  compare (PublicKey a b c) (PublicKey a' b' c') =
    compare [fromIntegral a,b,c] [fromIntegral a',b',c']

-- Program commandline flags

data Options = Options
  { verbose     :: Bool
  , connectAddr :: Maybe (HostName, Port)
  , listenPort  :: Port
  , bootstrap   :: Bool
  }

-- Default context

nullContext :: Context
nullContext = Context
  { ctxId     = Nothing
  , ctxAddr   = Nothing
  , ctxKey    = Nothing
  , lastField = Nothing
  , ctxHandle = Nothing
  , ctxPeers  = Nothing
  , ctxIsMe   = False
  , ctxIsLoop = False
  }
