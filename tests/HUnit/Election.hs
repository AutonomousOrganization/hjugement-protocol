{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
module HUnit.Election where

import Test.Tasty.HUnit
import qualified Data.Aeson as JSON
import qualified Data.List as List
import qualified Data.Text as Text
import qualified System.Random as Random

import Voting.Protocol

import Utils

hunit :: Reifies v Version => Proxy v -> TestTree
hunit v = testGroup "Election" $
 [ testGroup "groupGenInverses"
	 [ testCase "WeakParams" $
		reify weakFFC $ \(Proxy::Proxy c) ->
			List.take 10 (groupGenInverses @_ @c) @?=
				[groupGen^negate (fromNatural n) | n <- [0..9]]
	 , testCase "BeleniosParams" $
		reify beleniosFFC $ \(Proxy::Proxy c) ->
			List.take 10 (groupGenInverses @_ @c) @?=
				[groupGen^negate (fromNatural n) | n <- [0..9]]
	 ]
 , testGroup "encryptBallot" $
	 [ hunitsEncryptBallot v weakFFC
	 , hunitsEncryptBallot v beleniosFFC
	 ]
 ]

hunitsEncryptBallot ::
 Reifies v Version =>
 ReifyCrypto crypto => Key crypto => JSON.ToJSON crypto =>
 Proxy v -> crypto -> TestTree
hunitsEncryptBallot v crypto =
	testGroup (Text.unpack $ cryptoName crypto)
	 [ hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2","a3"] zero one]
		 [[True, False, False]]
		 (Right True)
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2","a3"] zero one]
		 [[False, False, False]]
		 (Right True)
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2","a3"] zero one]
		 [[False, False, False]]
		 (Right True)
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" [] zero one]
		 []
		 (Left (ErrorBallot_WrongNumberOfAnswers 0 1))
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2"] one one]
		 [[True]]
		 (Left (ErrorBallot_Answer (ErrorAnswer_WrongNumberOfOpinions 1 2)))
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2","a3"] zero one]
		 [[True, True, False]]
		 (Left (ErrorBallot_Answer (ErrorAnswer_WrongSumOfOpinions 2 0 1)))
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2","a3"] one one]
		 [[False, False, False]]
		 (Left (ErrorBallot_Answer (ErrorAnswer_WrongSumOfOpinions 0 1 1)))
	 , hunitEncryptBallot v crypto 0
		 [Question "q1" ["a1","a2"] one one]
		 [[False, False, True]]
		 (Left (ErrorBallot_Answer (ErrorAnswer_WrongNumberOfOpinions 3 2)))
	 , hunitEncryptBallot v crypto 0
		 [ Question "q1" ["a11","a12","a13"] zero (one+one)
		 , Question "q2" ["a21","a22","a23"] one one
		 ]
		 [ [True, False, True]
		 , [False, True, False] ]
		 (Right True)
	 ]

hunitEncryptBallot ::
 Reifies v Version =>
 ReifyCrypto crypto => Key crypto => JSON.ToJSON crypto =>
 Proxy v -> crypto -> Int -> [Question v] -> [[Bool]] ->
 Either ErrorBallot Bool -> TestTree
hunitEncryptBallot v election_crypto seed election_questions opins exp =
	let got =
		reifyCrypto election_crypto $ \(_c::Proxy c) ->
			runExcept $
			(`evalStateT` Random.mkStdGen seed) $ do
				election_uuid <- randomUUID
				cred <- randomCredential
				let ballotSecKey = credentialSecretKey @_ @c election_uuid cred
				election_public_key <- publicKey <$> randomSecretKey
				let elec = Election
					 { election_name        = "election"
					 , election_description = "description"
					 , election_hash        = hashElection elec
					 , election_version     = Just (reflect v)
					 , ..
					 }
				verifyBallot elec
				 <$> encryptBallot elec (Just ballotSecKey) opins
	in
	testCase (show opins) $
		got @?= exp
