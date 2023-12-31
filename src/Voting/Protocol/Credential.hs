{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
module Voting.Protocol.Credential where

import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), forM_, replicateM)
import Data.Bool
import Data.Char (Char)
import Data.Either (Either(..), either)
import Data.Eq (Eq(..))
import Data.Function (($))
import Data.Functor ((<$>))
import Data.Int (Int)
import Data.Maybe (maybe)
import Data.Ord (Ord(..))
import Data.Reflection (Reifies(..))
import Data.Semigroup (Semigroup(..))
import Data.Text (Text)
import GHC.Generics (Generic)
import Prelude (Integral(..), fromIntegral)
import Text.Show (Show(..))
import qualified Control.Monad.Trans.State.Strict as S
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import qualified Data.Char as Char
import qualified Data.List as List
import qualified Data.Text as Text
import qualified System.Random as Random

import Voting.Protocol.Arithmetic
import Voting.Protocol.Cryptography

-- * Class 'Key'
class Key crypto where
	-- | Type of cryptography, eg. "FFC".
	cryptoType :: crypto -> Text
	-- | Name of the cryptographic paramaters, eg. "Belenios".
	cryptoName :: crypto -> Text
	-- | Generate a random 'SecretKey'.
	randomSecretKey ::
	 Reifies c crypto =>
	 Monad m => Random.RandomGen r =>
	 S.StateT r m (SecretKey crypto c)
	-- | @('credentialSecretKey' uuid cred)@ returns the 'SecretKey'
	-- derived from given 'uuid' and 'cred'
	-- using 'Crypto.fastPBKDF2_SHA256'.
	credentialSecretKey ::
	 Reifies c crypto =>
	 UUID -> Credential -> SecretKey crypto c
	-- | @('publicKey' secKey)@ returns the 'PublicKey'
	-- derived from given 'SecretKey' @secKey@.
	publicKey ::
	 Reifies c crypto =>
	 SecretKey crypto c ->
	 PublicKey crypto c

-- * Type 'Credential'
-- | A 'Credential' is a word of @('tokenLength'+1 '==' 15)@-characters
-- from a base alphabet of (@'tokenBase' '==' 58)@ characters:
-- "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
-- (beware the absence of "0", \"O", \"I", and "l").
-- The last character is a checksum.
-- The entropy is: @('tokenLength' * log 'tokenBase' / log 2) '==' 82.01… bits@.
newtype Credential = Credential Text
 deriving (Eq,Show,Generic)
 deriving newtype NFData
 deriving newtype JSON.ToJSON
instance JSON.FromJSON Credential where
	parseJSON json@(JSON.String s) =
		either (\err -> JSON.typeMismatch ("Credential: "<>show err) json) return $
		readCredential s
	parseJSON json = JSON.typeMismatch "Credential" json

credentialAlphabet :: [Char] -- TODO: make this an array
credentialAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
tokenBase :: Int
tokenBase = List.length credentialAlphabet
tokenLength ::Int
tokenLength = 14

-- | @'randomCredential'@ generates a random 'Credential'.
randomCredential :: Monad m => Random.RandomGen r => S.StateT r m Credential
randomCredential = do
	rs <- replicateM tokenLength (randomR (fromIntegral tokenBase))
	let (tot, cs) = List.foldl' (\(acc,ds) d ->
			( acc * tokenBase + d
			, charOfDigit d : ds )
		 ) (zero::Int, []) rs
	let checksum = (negate tot + 53) `mod` 53 -- NOTE: why 53 and not 'tokenBase' ?
	return $ Credential $ Text.reverse $ Text.pack (charOfDigit checksum:cs)
	where
	charOfDigit = (credentialAlphabet List.!!)

-- | @'readCredential'@ reads and check the well-formedness of a 'Credential'
-- from raw 'Text'.
readCredential :: Text -> Either ErrorToken Credential
readCredential s
 | Text.length s /= tokenLength + 1 = Left ErrorToken_Length
 | otherwise = do
	tot <- Text.foldl'
	 (\acc c -> acc >>= \a -> ((a * tokenBase) +) <$> digitOfChar c)
	 (Right (zero::Int))
	 (Text.init s)
	checksum <- digitOfChar (Text.last s)
	if (tot + checksum) `mod` 53 == 0
	then Right (Credential s)
	else Left ErrorToken_Checksum
	where
	digitOfChar c =
		maybe (Left $ ErrorToken_BadChar c) Right $
		List.elemIndex c credentialAlphabet

-- ** Type 'ErrorToken'
data ErrorToken
 =   ErrorToken_BadChar Char.Char
 |   ErrorToken_Checksum
 |   ErrorToken_Length
 deriving (Eq,Show,Generic,NFData)

-- ** Type 'UUID'
newtype UUID = UUID Text
 deriving (Eq,Ord,Show,Generic)
 deriving anyclass (JSON.ToJSON)
 deriving newtype NFData
instance JSON.FromJSON UUID where
	parseJSON json@(JSON.String s) =
		either (\err -> JSON.typeMismatch ("UUID: "<>show err) json) return $
		readUUID s
	parseJSON json = JSON.typeMismatch "UUID" json

-- | @'randomUUID'@ generates a random 'UUID'.
randomUUID ::
 Monad m =>
 Random.RandomGen r =>
 S.StateT r m UUID
randomUUID = do
	rs <- replicateM tokenLength (randomR (fromIntegral tokenBase))
	return $ UUID $ Text.pack $ charOfDigit <$> rs
	where
	charOfDigit = (credentialAlphabet List.!!)

-- | @'readCredential'@ reads and check the well-formedness of a 'Credential'
-- from raw 'Text'.
readUUID :: Text -> Either ErrorToken UUID
readUUID s
 | Text.length s /= tokenLength = Left ErrorToken_Length
 | otherwise = do
	forM_ (Text.unpack s) digitOfChar
	return (UUID s)
	where
	digitOfChar c =
		maybe (Left $ ErrorToken_BadChar c) Right $
		List.elemIndex c credentialAlphabet
