module Utils
 ( module Test.Tasty
 , module Data.Bool
 , module Voting.Protocol.Utils
 , Applicative(..)
 , Monad(..), forM, mapM, replicateM, unless, when
 , Eq(..)
 , Either(..), either, isLeft, isRight
 , ($), (.), id, const, flip
 , (<$>)
 , Int
 , Maybe(..)
 , Monoid(..), Semigroup(..)
 , Ord(..)
 , String
 , Text
 , Word8
 , Num, Fractional(..), Integral(..), Integer, fromIntegral
 , Show(..)
 , MonadTrans(..)
 , ExceptT
 , runExcept
 , throwE
 , StateT(..)
 , evalStateT
 , modify'
 , mkStdGen
 , debug
 , nCk
 , combinOfRank
 ) where

import Control.Applicative (Applicative(..))
import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.Trans.Except
import Control.Monad.Trans.State.Strict
import Data.Bool
import Data.Either (Either(..), either, isLeft, isRight)
import Data.Eq (Eq(..))
import Data.Function
import Data.Functor ((<$>))
import Data.Int (Int)
import Data.Maybe (Maybe(..))
import Data.Monoid (Monoid(..))
import Data.Ord (Ord(..))
import Data.Semigroup (Semigroup(..))
import Data.String (String)
import Data.Text (Text)
import Data.Word (Word8)
import Debug.Trace
import Prelude (Num(..), Fractional(..), Integral(..), Integer, undefined, fromIntegral)
import System.Random (mkStdGen)
import Test.Tasty
import Text.Show (Show(..))

import Voting.Protocol.Utils

debug :: Show a => String -> a -> a
debug msg x = trace (msg<>": "<>show x) x

-- | @'nCk' n k@ returns the number of combinations
-- of size 'k' from a set of size 'n'.
--
-- Computed using the formula:
-- @'nCk' n (k+1) == 'nCk' n (k-1) * (n-k+1) / k@
nCk :: Integral i => i -> i -> i
n`nCk`k | n<0||k<0||n<k = undefined
        | otherwise     = go 1 1
        where
        go i acc = if k' < i then acc else go (i+1) (acc * (n-i+1) `div` i)
        -- Use a symmetry to compute over smaller numbers,
        -- which is more efficient and safer
        k' = if n`div`2 < k then n-k else k

-- | @'combinOfRank' n k r@ returns the @r@-th combination
-- of @k@ elements from a set of @n@ elements.
-- DOC: <http://www.site.uottawa.ca/~lucia/courses/5165-09/GenCombObj.pdf>, p.26
combinOfRank :: Integral i => i -> i -> i -> [i]
combinOfRank n k rk | rk<0||n`nCk`k<rk = undefined
                    | otherwise = for1K 1 1 rk
	where
	for1K i j r | i <  k    = uptoRank i j r
	            | i == k    = [j+r] -- because when i == k, nbCombs is always 1
	            | otherwise = []
	uptoRank i j r | nbCombs <- (n-j)`nCk`(k-i)
	               , nbCombs <= r = uptoRank i (j+1) (r-nbCombs)
	               | otherwise    = j : for1K (i+1) (j+1) r
