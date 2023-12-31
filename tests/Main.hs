module Main where

import Data.Function (($))
import HUnit
import QuickCheck
import System.IO (IO)
import Test.Tasty
import Voting.Protocol

main :: IO ()
main =
	defaultMain $
	reify stableVersion $ \v ->
	testGroup "Voting.Protocol"
	 [ hunits v
	 , quickchecks v
	 ]
