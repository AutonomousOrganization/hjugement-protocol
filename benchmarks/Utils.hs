module Utils
 ( module Criterion.Main
 , module Data.Bool
 , Applicative(..)
 , Monad(..), forM, join, replicateM, unless, when
 , Eq(..)
 , Either(..), either, isLeft, isRight
 , ($), (.), id, const, flip
 , (<$>)
 , Int
 , IO
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
 , StateT
 , evalStateT
 , mkStdGen
 , error
 , debug
 ) where

import Control.Applicative (Applicative(..))
import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.Trans.Except
import Control.Monad.Trans.State.Strict
import Criterion.Main
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
import Prelude (Num(..), Fractional(..), Integral(..), Integer, fromIntegral, error)
import System.IO (IO)
import System.Random (mkStdGen)
import Text.Show (Show(..))

debug :: Show a => String -> a -> a
debug msg x = trace (msg<>": "<>show x) x

