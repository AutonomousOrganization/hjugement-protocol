module Main where

import Criterion.Main
import qualified Election
import Utils

main :: IO ()
main =
	defaultMain $ join
	 [ Election.benchmarks
	 ]
