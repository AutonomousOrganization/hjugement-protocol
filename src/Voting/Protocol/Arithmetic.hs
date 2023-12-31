{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-} -- for ReifyCrypto
module Voting.Protocol.Arithmetic where

import Control.Arrow (first)
import Control.DeepSeq (NFData)
import Control.Monad (Monad(..))
import Data.Aeson (ToJSON(..),FromJSON(..))
import Data.Bits
import Data.Bool
import Data.Eq (Eq(..))
import Data.Foldable (Foldable, foldl')
import Data.Function (($), (.), id)
import Data.Int (Int)
import Data.Maybe (Maybe(..), fromJust)
import Data.Ord (Ord(..))
import Data.Proxy (Proxy(..))
import Data.Reflection (Reifies(..))
import Data.String (IsString(..))
import GHC.Natural (minusNaturalMaybe)
import Numeric.Natural (Natural)
import Prelude (Integer, Bounded(..), Integral(..), fromIntegral, Enum(..))
import Text.Read (readMaybe)
import Text.Show (Show(..))
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import qualified Data.ByteString as BS
import qualified Data.Char as Char
import qualified Data.List as List
import qualified Data.Text as Text
import qualified Prelude as Num
import qualified System.Random as Random

-- * Class 'CryptoParams' where
class
 ( EuclideanRing (G crypto c)
 , FromNatural   (G crypto c)
 , ToNatural     (G crypto c)
 , Eq            (G crypto c)
 , Ord           (G crypto c)
 , Show          (G crypto c)
 , NFData        (G crypto c)
 , FromJSON      (G crypto c)
 , ToJSON        (G crypto c)
 , Reifies c crypto
 ) => CryptoParams crypto c where
	-- | A generator of the subgroup.
	groupGen   :: G crypto c
	-- | The order of the subgroup.
	groupOrder :: Proxy c -> Natural
	
	-- | 'groupGenPowers' returns the infinite list
	-- of powers of 'groupGen'.
	--
	-- NOTE: In the 'CryptoParams' class to keep
	-- computed values in memory across calls to 'groupGenPowers'.
	groupGenPowers :: [G crypto c]
	groupGenPowers = go one
		where go g = g : go (g * groupGen)
	
	-- | 'groupGenInverses' returns the infinite list
	-- of 'inverse' powers of 'groupGen':
	-- @['groupGen' '^' 'negate' i | i <- [0..]]@,
	-- but by computing each value from the previous one.
	--
	-- NOTE: In the 'CryptoParams' class to keep
	-- computed values in memory across calls to 'groupGenInverses'.
	--
	-- Used by 'intervalDisjunctions'.
	groupGenInverses :: [G crypto c]
	groupGenInverses = go one
		where
		invGen = inverse groupGen
		go g = g : go (g * invGen)

-- ** Class 'ReifyCrypto'
class ReifyCrypto crypto where
	-- | Like 'reify' but augmented with the 'CryptoParams' constraint.
	reifyCrypto :: crypto -> (forall c. Reifies c crypto => CryptoParams crypto c => Proxy c -> r) -> r

-- * Class 'Additive'
-- | An additive semigroup.
class Additive a where
	zero :: a
	(+) :: a -> a -> a; infixl 6 +
	sum :: Foldable f => f a -> a
	sum = foldl' (+) zero
instance Additive Natural where
	zero = 0
	(+)  = (Num.+)
instance Additive Integer where
	zero = 0
	(+)  = (Num.+)
instance Additive Int where
	zero = 0
	(+)  = (Num.+)

-- * Class 'Semiring'
-- | A multiplicative semigroup, with an additive semigroup (aka. a semiring).
class Additive a => Semiring a where
	one :: a
	(*) :: a -> a -> a; infixl 7 *
instance Semiring Natural where
	one = 1
	(*) = (Num.*)
instance Semiring Integer where
	one = 1
	(*) = (Num.*)
instance Semiring Int where
	one = 1
	(*) = (Num.*)

-- | @(b '^' e)@ returns the modular exponentiation of base 'b' by exponent 'e'.
(^) ::
 forall crypto c.
 Reifies c crypto =>
 Semiring (G crypto c) =>
 G crypto c -> E crypto c -> G crypto c
(^) b (E e)
 | e == 0 = one
 | otherwise = t * (b*b) ^ E (e`shiftR`1)
	where t | testBit e 0 = b
	        | otherwise   = one
infixr 8 ^

-- ** Class 'Ring'
-- | A semiring that support substraction (aka. a ring).
class Semiring a => Ring a where
	negate :: a -> a
	(-) :: a -> a -> a; infixl 6 -
	x-y = x + negate y
instance Ring Integer where
	negate  = Num.negate
instance Ring Int where
	negate  = Num.negate

-- ** Class 'EuclideanRing'
-- | A commutative ring that support division (aka. an euclidean ring).
class Ring a => EuclideanRing a where
	inverse :: a -> a
	(/) :: a -> a -> a; infixl 7 /
	x/y = x * inverse y

-- ** Type 'G'
-- | The type of the elements of a subgroup of a field.
newtype G crypto c = G { unG :: FieldElement crypto }

-- *** Type family 'FieldElement'
type family FieldElement crypto :: *

-- ** Type 'E'
-- | An exponent of a (cyclic) subgroup of a field.
-- The value is always in @[0..'groupOrder'-1]@.
newtype E crypto c = E { unE :: Natural }
 deriving (Eq,Ord,Show)
 deriving newtype NFData
instance ToJSON (E crypto c) where
	toJSON = JSON.toJSON . show . unE
instance CryptoParams crypto c => FromJSON (E crypto c) where
	parseJSON (JSON.String s)
	 | Just (c0,_) <- Text.uncons s
	 , c0 /= '0'
	 , Text.all Char.isDigit s
	 , Just x <- readMaybe (Text.unpack s)
	 , x < groupOrder (Proxy @c)
	 = return (E x)
	parseJSON json = JSON.typeMismatch "Exponent" json
instance CryptoParams crypto c => FromNatural (E crypto c) where
	fromNatural n = E $ n `mod` groupOrder (Proxy @c)
instance ToNatural (E crypto c) where
	nat = unE
instance CryptoParams crypto c => Additive (E crypto c) where
	zero = E zero
	E x + E y = E $ (x + y) `mod` groupOrder (Proxy @c)
instance CryptoParams crypto c => Semiring (E crypto c) where
	one = E one
	E x * E y = E $ (x * y) `mod` groupOrder (Proxy @c)
instance CryptoParams crypto c => Ring (E crypto c) where
	negate (E x) = E $ fromJust $ groupOrder (Proxy @c)`minusNaturalMaybe`x
instance CryptoParams crypto c => Random.Random (E crypto c) where
	randomR (E lo, E hi) =
		first (E . fromIntegral) .
		Random.randomR
		 ( 0`max`toInteger lo
		 , toInteger hi`min`(toInteger (groupOrder (Proxy @c)) - 1) )
	random =
		first (E . fromIntegral) .
		Random.randomR (0, toInteger (groupOrder (Proxy @c)) - 1)
instance CryptoParams crypto c => Enum (E crypto c) where
	toEnum = fromNatural . fromIntegral
	fromEnum = fromIntegral . nat
	enumFromTo lo hi = List.unfoldr
	 (\i -> if i<=hi then Just (i, i+one) else Nothing) lo
instance CryptoParams crypto c => Bounded (E crypto c) where
	minBound = zero
	maxBound = E $ fromJust $ groupOrder (Proxy @c)`minusNaturalMaybe`1

-- * Class 'FromNatural'
class FromNatural a where
	fromNatural :: Natural -> a
instance FromNatural Natural where
	fromNatural = id

-- * Class 'ToNatural'
class ToNatural a where
	nat :: a -> Natural
instance ToNatural Natural where
	nat = id

-- | @('bytesNat' x)@ returns the serialization of 'x'.
bytesNat :: ToNatural n => n -> BS.ByteString
bytesNat = fromString . show . nat
