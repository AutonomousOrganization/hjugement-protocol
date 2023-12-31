{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies instances
{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Finite Field Cryptography (FFC)
-- is a method of implementing discrete logarithm cryptography
-- using finite field mathematics.
module Voting.Protocol.FFC where

import Control.Arrow (first)
import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), unless)
import Data.Aeson (ToJSON(..), FromJSON(..), (.:), (.:?), (.=))
import Data.Bool
import Data.Either (Either(..))
import Data.Eq (Eq(..))
import Data.Function (($), (.))
import Data.Functor ((<$>))
import Data.Maybe (Maybe(..), fromMaybe, fromJust)
import Data.Monoid (Monoid(..))
import Data.Ord (Ord(..))
import Data.Proxy (Proxy(..))
import Data.Reflection (Reifies(..), reify)
import Data.Semigroup (Semigroup(..))
import Data.Text (Text)
import GHC.Generics (Generic)
import GHC.Natural (minusNaturalMaybe)
import Numeric.Natural (Natural)
import Prelude (Integral(..), fromIntegral)
import Text.Read (readMaybe, readEither)
import Text.Show (Show(..))
import qualified Crypto.KDF.PBKDF2 as Crypto
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import qualified Data.Char as Char
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified System.Random as Random

import Voting.Protocol.Arithmetic
import Voting.Protocol.Cryptography
import Voting.Protocol.Credential

-- * Type 'FFC'
-- | Mutiplicative subgroup of a Finite Prime Field.
--
-- NOTE: an 'FFC' term-value is brought into the context of many functions
-- through a type-variable @c@ whose 'Reifies' constraint enables to 'reflect'
-- that 'FFC' at the term-level (a surprising technique but a very useful one).
-- Doing like this is simpler than working in a 'Monad' (like a 'Reader'),
-- and enables that 'FFC' term to be used simply in instances' methods
-- not supporting an inner 'Monad', like 'parseJSON', 'randomR', 'fromEnum' or 'arbitrary'.
-- Aside from that, the sharing of 'FFC' amongst several types
-- is encoded at the type-level by including @c@
-- as a phantom type of 'F', 'G' and 'E'.
data FFC = FFC
 {   ffc_name :: !Text
 ,   ffc_fieldCharac :: !Natural
     -- ^ The prime number characteristic of a Finite Prime Field.
     --
     -- ElGamal's hardness to decrypt requires a large prime number
     -- to form the multiplicative subgroup.
 ,   ffc_groupGen :: !Natural
     -- ^ A generator of the multiplicative subgroup of the Finite Prime Field.
     --
     -- NOTE: since 'ffc_fieldCharac' is prime,
     -- the multiplicative subgroup is cyclic,
     -- and there are phi('fieldCharac'-1) many choices for the generator of the group,
     -- where phi is the Euler totient function.
 ,   ffc_groupOrder :: !Natural
     -- ^ The order of the subgroup.
     --
     -- WARNING: 'ffc_groupOrder' MUST be a prime number dividing @('ffc_fieldCharac'-1)@
     -- to ensure that ElGamal is secure in terms of the DDH assumption.
 } deriving (Eq,Show,Generic,NFData)
instance ToJSON FFC where
	toJSON FFC{..} =
		JSON.object $
		 (if Text.null ffc_name then [] else ["name" .= ffc_name] ) <>
		 [ "p" .= show ffc_fieldCharac
		 , "g" .= show ffc_groupGen
		 , "q" .= show ffc_groupOrder
		 ]
	toEncoding FFC{..} =
		JSON.pairs $
			(if Text.null ffc_name then mempty else "name" .= ffc_name) <>
			"p" .= show ffc_fieldCharac <>
			"g" .= show ffc_groupGen <>
			"q" .= show ffc_groupOrder
instance FromJSON FFC where
	parseJSON = JSON.withObject "FFC" $ \o -> do
		ffc_name <- fromMaybe "" <$> (o .:? "name")
		p <- o .: "p"
		g <- o .: "g"
		q <- o .: "q"
		-- TODO: check p is probable prime
		-- TODO: check q is probable prime
		ffc_fieldCharac <- case readEither (Text.unpack p) of
		 Left err -> JSON.typeMismatch ("FFC: fieldCharac: "<>err) (JSON.String p)
		 Right a -> return a
		ffc_groupGen <- case readEither (Text.unpack g) of
		 Left err -> JSON.typeMismatch ("FFC: groupGen: "<>err) (JSON.String g)
		 Right a -> return a
		ffc_groupOrder <- case readEither (Text.unpack q) of
		 Left err -> JSON.typeMismatch ("FFC: groupOrder: "<>err) (JSON.String q)
		 Right a -> return a
		unless (nat ffc_groupGen < ffc_fieldCharac) $
			JSON.typeMismatch "FFC: groupGen is not lower than fieldCharac" (JSON.Object o)
		unless (ffc_groupOrder < ffc_fieldCharac) $
			JSON.typeMismatch "FFC: groupOrder is not lower than fieldCharac" (JSON.Object o)
		unless (nat ffc_groupGen > 1) $
			JSON.typeMismatch "FFC: groupGen is not greater than 1" (JSON.Object o)
		unless (fromJust (ffc_fieldCharac`minusNaturalMaybe`one) `rem` ffc_groupOrder == 0) $
			JSON.typeMismatch "FFC: groupOrder does not divide fieldCharac-1" (JSON.Object o)
		return FFC{..}
instance Reifies c FFC => CryptoParams FFC c where
	groupGen = G $ ffc_groupGen $ reflect (Proxy::Proxy c)
	groupOrder c = ffc_groupOrder $ reflect c
instance ReifyCrypto FFC where
	reifyCrypto = reify
instance Key FFC where
	cryptoType _ = "FFC"
	cryptoName = ffc_name
	randomSecretKey = random
	credentialSecretKey (UUID uuid) (Credential cred) =
		fromNatural $ decodeBigEndian $
		Crypto.fastPBKDF2_SHA256
		 Crypto.Parameters
		 { Crypto.iterCounts   = 1000
		 , Crypto.outputLength = 32 -- bytes, ie. 256 bits
		 }
		 (Text.encodeUtf8 cred)
		 (Text.encodeUtf8 uuid)
	publicKey = (groupGen @FFC ^)

fieldCharac :: forall c. Reifies c FFC => Natural
fieldCharac = ffc_fieldCharac $ reflect (Proxy::Proxy c)

-- ** Examples
-- | Weak parameters for debugging purposes only.
weakFFC :: FFC
weakFFC = FFC
 { ffc_name        = "weakFFC"
 , ffc_fieldCharac = 263
 , ffc_groupGen    = 2
 , ffc_groupOrder  = 131
 }

-- | Parameters used in Belenios.
-- A 2048-bit 'fieldCharac' of a Finite Prime Field,
-- with a 256-bit 'groupOrder' for a multiplicative subgroup
-- generated by 'groupGen'.
beleniosFFC :: FFC
beleniosFFC = FFC
 { ffc_name        = "beleniosFFC"
 , ffc_fieldCharac = 20694785691422546401013643657505008064922989295751104097100884787057374219242717401922237254497684338129066633138078958404960054389636289796393038773905722803605973749427671376777618898589872735865049081167099310535867780980030790491654063777173764198678527273474476341835600035698305193144284561701911000786737307333564123971732897913240474578834468260652327974647951137672658693582180046317922073668860052627186363386088796882120769432366149491002923444346373222145884100586421050242120365433561201320481118852408731077014151666200162313177169372189248078507711827842317498073276598828825169183103125680162072880719
 , ffc_groupGen    =  2402352677501852209227687703532399932712287657378364916510075318787663274146353219320285676155269678799694668298749389095083896573425601900601068477164491735474137283104610458681314511781646755400527402889846139864532661215055797097162016168270312886432456663834863635782106154918419982534315189740658186868651151358576410138882215396016043228843603930989333662772848406593138406010231675095763777982665103606822406635076697764025346253773085133173495194248967754052573659049492477631475991575198775177711481490920456600205478127054728238140972518639858334115700568353695553423781475582491896050296680037745308460627
 , ffc_groupOrder  = 78571733251071885079927659812671450121821421258408794611510081919805623223441
 }

-- | The type of the elements of a Finite Prime Field.
--
-- A field must satisfy the following properties:
--
-- * @(f, ('+'), 'zero')@ forms an abelian group,
--   called the additive group of 'f'.
--
-- * @('NonNull' f, ('*'), 'one')@ forms an abelian group,
--   called the multiplicative group of 'f'.
--
-- * ('*') is associative:
--   @(a'*'b)'*'c == a'*'(b'*'c)@ and
--   @a'*'(b'*'c) == (a'*'b)'*'c@.
--
-- * ('*') and ('+') are both commutative:
--   @a'*'b == b'*'a@ and
--   @a'+'b == b'+'a@
--
-- * ('*') and ('+') are both left and right distributive:
--   @a'*'(b'+'c) == (a'*'b) '+' (a'*'c)@ and
--   @(a'+'b)'*'c == (a'*'c) '+' (b'*'c)@
--
-- The 'Natural' is always within @[0..'fieldCharac'-1]@.
type instance FieldElement FFC = Natural
deriving newtype instance Eq     (G FFC c)
deriving newtype instance Ord    (G FFC c)
deriving newtype instance NFData (G FFC c)
deriving newtype instance Show   (G FFC c)
instance Reifies c FFC => FromJSON (G FFC c) where
	parseJSON (JSON.String s)
	 | Just (c0,_) <- Text.uncons s
	 , c0 /= '0'
	 , Text.all Char.isDigit s
	 , Just x <- readMaybe (Text.unpack s)
	 , x < fieldCharac @c
	 , r <- G x
	 , r ^ E (groupOrder @FFC (Proxy @c)) == one
	 = return r
	parseJSON json = JSON.typeMismatch "GroupElement" json
instance ToJSON (G FFC c) where
	toJSON (G x) = JSON.toJSON (show x)
instance Reifies c FFC => FromNatural (G FFC c) where
	fromNatural i = G $ abs $ i `mod` fieldCharac @c
		where
		abs x | x < 0 = x + fieldCharac @c
		      | otherwise = x
instance ToNatural (G FFC c) where
	nat = unG
instance Reifies c FFC => Additive (G FFC c) where
	zero = G 0
	G x + G y = G $ (x + y) `mod` fieldCharac @c
instance Reifies c FFC => Semiring (G FFC c) where
	one = G 1
	G x * G y = G $ (x * y) `mod` fieldCharac @c
instance Reifies c FFC => Ring (G FFC c) where
	negate (G x)
	 | x == 0 = zero
	 | otherwise = G $ fromJust $ nat (fieldCharac @c)`minusNaturalMaybe`x
instance Reifies c FFC => EuclideanRing (G FFC c) where
	-- | NOTE: add 'groupOrder' so the exponent given to (^) is positive.
	inverse = (^ E (fromJust $ groupOrder @FFC (Proxy @c)`minusNaturalMaybe`1))
instance Reifies c FFC => Random.Random (G FFC c) where
	randomR (G lo, G hi) =
		first (G . fromIntegral) .
		Random.randomR
		 ( 0`max`toInteger lo
		 , toInteger hi`min`(toInteger (fieldCharac @c) - 1) )
	random =
		first (G . fromIntegral) .
		Random.randomR (0, toInteger (fieldCharac @c) - 1)
