{-# LANGUAGE OverloadedStrings #-}
module HUnit.FFC where

import GHC.Natural (minusNaturalMaybe)
import Data.Maybe (fromJust)
import Test.Tasty.HUnit
import Voting.Protocol
import Utils
import qualified Data.Text as Text

hunit :: Reifies v Version => Proxy v -> TestTree
hunit _v = testGroup "FFC"
 [ testGroup "inverse"
	 [ hunitInv weakFFC
	 , hunitInv beleniosFFC
	 ]
 , testGroup "hash"
	 [ testGroup "WeakParams" $
		reify weakFFC $ \(Proxy::Proxy c) ->
		 [ testCase "[groupGen]" $
			hash "start" [groupGen :: G FFC c] @?=
				fromNatural 62
		 , testCase "[groupGen, groupGen]" $
			hash "start" [groupGen :: G FFC c, groupGen] @?=
				fromNatural 31
		 ]
	 , testGroup "BeleniosParams" $
		reify beleniosFFC $ \(Proxy::Proxy c) ->
		 [ testCase "[groupGen]" $
			hash "start" [groupGen :: G FFC c] @?=
				fromNatural 75778590284190557660612328423573274641033882642784670156837892421285248292707
		 , testCase "[groupGen, groupGen]" $
			hash "start" [groupGen :: G FFC c, groupGen] @?=
				fromNatural 28798937720387703653439047952832768487958170248947132321730024269734141660223
		 ]
	 ]
 ]

hunitInv ::
 forall crypto.
 ReifyCrypto crypto => Key crypto =>
 crypto -> TestTree
hunitInv crypto =
	testGroup (Text.unpack $ cryptoName crypto)
	 [ testCase "groupGen" $
			reifyCrypto crypto $ \(_c::Proxy c) ->
				inverse (groupGen :: G crypto c) @?=
					groupGen ^ E (fromJust $ groupOrder (Proxy @c) `minusNaturalMaybe` one)
	 ]
