import Codec.Crypto.RSA (PublicKey)
import Data.ByteString (ByteString)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

import qualified Data.ByteString.Base64 as B64 (encode, decode)

-- Cryptographic hash for identifying users

type Hash = PublicKey

-- Name for identifying users more familiarly

type Name = String

-- Packet structure

data Packet = Packet RoutingHeader Content

type RoutingHeader = [RSection]
type Content       = [CSection]

-- Immediate data representation of all available sections, type and structure safe

data RSection =
    Target TargetType (Maybe Address)
  | Source Hash (Base64 Signature)
  | SourceAddr Address
  | Version Int
  | Support Int
  | Drop Address


data CSection =
    Message MessageType (Base64 (Either ByteString (AES ByteString)))
  | Key (RSA64 Key))

  -- Hash table interactions

  | WhoIs (RSA64 Name)
  | ThisIs (RSA64 Name) (RSA64 Hash)
  | NoExist (RSA64 Name)
  | Register (RSA64 Name)
  | Exist (RSA64 Name)

  -- Location table interactions

  | WhereIs (RSA64 Hash)
  | HereIs (RSA64 Hash) (RSA64 Address)
  | NotFound (RSA64 Hash)
  | Update (RSA64 Address)

-- Helpers

type RSA64 t = Base64 (RSA t)
type AES64 t = Base64 (AES t)

toMaybe :: Either a b -> Maybe b
toMaybe = either (const Nothing) Just

-- Safety types for Base64 and encryption; only used to enforce parsing/serializing rules

newtype Base64 t = Base64 t
newtype AES t    = AES t
newtype RSA t    = RSA t


-- Type class for serializable / unserializable types, per protocol

class Serializable s where
  encode :: s -> ByteString
  decode :: ByteString -> Maybe s


-- Type instances for above types

instance Serializable ByteString where
  encode = id
  decode = Just

instance Serializable Text where
  encode = encodeUtf8
  decode = toMaybe . decodeUtf8'

instance Serializable String where
  encode   = encode . fromString
  decode c = unpack `fmap` decode c

instance Serializable Hash where
  -- TODO

instance Serializable t => Serializable (Base64 t) where
  encode (Base64 t) = B64.encode (encode t)
  decode (Base64 t) = toMaybe $ B64.decode (decode t)

instance Serializable t => Serializable (RSA t) where
  encode (RSA t) = -- ...
  decode (RSA t) =

instance Serializable t => Serializable (AES t) where
  encode (AES t) =
  decode (AES t) =
