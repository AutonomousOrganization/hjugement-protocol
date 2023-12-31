{-# OPTIONS_GHC -fno-warn-orphans #-}
module Voting.Protocol.Utils where

import Control.Applicative (Applicative(..))
import Control.Arrow (first)
import Data.Bool
import Data.Either (Either(..), either)
import Data.Eq (Eq(..))
import Data.Foldable (sequenceA_)
import Data.Function (($), (.))
import Data.Functor ((<$))
import Data.Maybe (Maybe(..), maybe, listToMaybe)
import Data.String (String)
import Data.Traversable (Traversable(..))
import Data.Tuple (uncurry)
import Numeric.Natural (Natural)
import Prelude (Integer, fromIntegral)
import qualified Data.Aeson.Internal as JSON
import qualified Data.List as List
import qualified System.Random as Random
import qualified Text.ParserCombinators.ReadP as Read
import qualified Text.Read as Read

-- | Like ('.') but with two arguments.
o2 :: (c -> d) -> (a -> b -> c) -> a -> b -> d
o2 f g = \x y -> f (g x y)
infixr 9 `o2`
{-# INLINE o2 #-}

-- | NOTE: check the lengths before applying @f@.
isoZipWith :: (a->b->c) -> [a]->[b]->Maybe [c]
isoZipWith f as bs
 | List.length as /= List.length bs = Nothing
 | otherwise = Just (List.zipWith f as bs)

-- | NOTE: check the lengths before applying @f@.
isoZipWith3 :: (a->b->c->d) -> [a]->[b]->[c]->Maybe [d]
isoZipWith3 f as bs cs
 | al /= List.length bs = Nothing
 | al /= List.length cs = Nothing
 | otherwise = Just (List.zipWith3 f as bs cs)
 where al = List.length as

isoZipWithM ::
 Applicative f =>
 f () -> (a->b->f c) -> [a]->[b]->f [c]
isoZipWithM err f as bs =
	maybe ([] <$ err) sequenceA $
		isoZipWith f as bs

isoZipWithM_ ::
 Applicative f =>
 f () -> (a->b->f c) -> [a]->[b]->f ()
isoZipWithM_ err f as bs =
	maybe err sequenceA_ $
		isoZipWith f as bs

isoZipWith3M ::
 Applicative f =>
 f () -> (a->b->c->f d) -> [a]->[b]->[c]->f [d]
isoZipWith3M err f as bs cs =
	maybe ([] <$ err) sequenceA $
		isoZipWith3 f as bs cs

isoZipWith3M_ ::
 Applicative f =>
 f () -> (a->b->c->f d) -> [a]->[b]->[c]->f ()
isoZipWith3M_ err f as bs cs =
	maybe err sequenceA_ $
		isoZipWith3 f as bs cs

-- * JSON utils

-- | Copied from 'Data.Aeson''s 'eitherFormatError'
-- which is not exported.
jsonEitherFormatError :: Either (JSON.JSONPath, String) a -> Either String a
jsonEitherFormatError = either (Left . uncurry JSON.formatError) Right
{-# INLINE jsonEitherFormatError #-}

instance Random.Random Natural where
	randomR (mini,maxi) =
		first (fromIntegral::Integer -> Natural) .
		Random.randomR (fromIntegral mini, fromIntegral maxi)
	random = first (fromIntegral::Integer -> Natural) . Random.random

-- * Parsing utils

parseReadP :: Read.ReadP a -> String -> Maybe a
parseReadP p s =
	let p' = Read.readP_to_S p in
	listToMaybe $ do
		(x, "") <- p' s
		pure x
