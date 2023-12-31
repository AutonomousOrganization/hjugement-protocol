{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies constraints in instances
module Voting.Protocol.Version where

import Control.Applicative (Applicative(..), Alternative(..))
import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), join, replicateM)
import Control.Monad.Trans.Except (ExceptT(..), throwE)
import Data.Aeson (ToJSON(..), FromJSON(..), (.:), (.=))
import Data.Bits
import Data.Bool
import Data.Eq (Eq(..))
import Data.Function (($), (.), id)
import Data.Functor (Functor, (<$>), (<$))
import Data.Maybe (Maybe(..), fromJust, listToMaybe)
import Data.Ord (Ord(..))
import Data.Proxy (Proxy(..))
import Data.Reflection (Reifies(..))
import Data.Semigroup (Semigroup(..))
import Data.String (String, IsString(..))
import Data.Text (Text)
import GHC.Generics (Generic)
import GHC.Natural (minusNaturalMaybe)
import GHC.TypeLits (Nat, Symbol, natVal, symbolVal, KnownNat, KnownSymbol)
import Numeric.Natural (Natural)
import Prelude (Bounded(..), fromIntegral)
import System.Random (RandomGen)
import Text.Show (Show(..), showChar, showString, shows)
import qualified Control.Monad.Trans.State.Strict as S
import qualified Crypto.Hash as Crypto
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as BS64
import qualified Data.Char as Char
import qualified Data.List as List
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Builder as TLB
import qualified Data.Text.Lazy.Builder.Int as TLB
import qualified System.Random as Random
import qualified Text.ParserCombinators.ReadP as Read
import qualified Text.Read as Read

import Voting.Protocol.Utils
import Voting.Protocol.Arithmetic

-- * Type 'Version'
-- | Version of the Helios-C protocol.
data Version = Version
 { version_branch :: [Natural]
 , version_tags   :: [(Text, Natural)]
 } deriving (Eq,Ord,Generic,NFData)
instance IsString Version where
	fromString = fromJust . readVersion
instance Show Version where
	showsPrec _p Version{..} =
		List.foldr (.) id
		 (List.intersperse (showChar '.') $
			shows <$> version_branch) .
		List.foldr (.) id
		 ((\(t,n) -> showChar '-' . showString (Text.unpack t) .
			if n > 0 then shows n else id)
		 <$> version_tags)
instance ToJSON Version where
	toJSON     = toJSON     . show
	toEncoding = toEncoding . show
instance FromJSON Version where
	parseJSON (JSON.String s)
	 | Just v <- readVersion (Text.unpack s)
	 = return v
	parseJSON json = JSON.typeMismatch "Version" json

hasVersionTag :: Version -> Text -> Bool
hasVersionTag v tag = List.any (\(t,_n) -> t == tag) (version_tags v)

-- ** Type 'ExperimentalVersion'
type ExperimentalVersion = V [1,6] '[ '(VersionTagQuicker,0)]
experimentalVersion :: Version
experimentalVersion = stableVersion{version_tags = [(versionTagQuicker,0)]}

-- ** Type 'StableVersion'
type StableVersion = V [1,6] '[]
stableVersion :: Version
stableVersion = "1.6"

-- ** Type 'VersionTagQuicker'
type VersionTagQuicker = "quicker"
versionTagQuicker :: Text
versionTagQuicker = "quicker"

readVersion :: String -> Maybe Version
readVersion = parseReadP $ do
	version_branch <- Read.sepBy1
	 (Read.read <$> Read.munch1 Char.isDigit)
	 (Read.char '.')
	version_tags <- Read.many $ (,)
		 <$> (Text.pack <$ Read.char '-' <*> Read.munch1 Char.isAlpha)
		 <*> (Read.read <$> Read.munch1 Char.isDigit <|> return 0)
	return Version{..}

-- ** Type 'V'
-- | Type-level representation of a specific 'Version'.
data V (branch::[Nat]) (tags::[(Symbol,Nat)])
-- | Like a normal 'reflect' but this one takes
-- its 'Version' from a type-level 'V'ersion
-- instead of a term-level 'Version'.
instance (VersionBranchVal branch, VersionTagsVal tags) => Reifies (V branch tags) Version where
	reflect _ = Version
	 { version_branch = versionBranchVal (Proxy @branch)
	 , version_tags   = versionTagsVal (Proxy @tags)
	 }

-- *** Class 'VersionBranchVal'
class VersionBranchVal a where
	versionBranchVal :: proxy a -> [Natural]
instance KnownNat h => VersionBranchVal '[h] where
	versionBranchVal _ = [fromIntegral (natVal (Proxy @h))]
instance
 ( KnownNat h
 , KnownNat hh
 , VersionBranchVal (hh ':t)
 ) => VersionBranchVal (h ': hh ': t) where
	versionBranchVal _ =
		fromIntegral (natVal (Proxy @h)) :
		versionBranchVal (Proxy @(hh ':t))

-- *** Class 'VersionTagsVal'
class VersionTagsVal a where
	versionTagsVal :: proxy a -> [(Text,Natural)]
instance VersionTagsVal '[] where
	versionTagsVal _ = []
instance
 ( KnownSymbol s
 , KnownNat n
 , VersionTagsVal t
 ) => VersionTagsVal ('(s,n) ': t) where
	versionTagsVal _ =
		( Text.pack (symbolVal (Proxy @s))
		, fromIntegral (natVal (Proxy @n))
		) : versionTagsVal (Proxy :: Proxy t)
