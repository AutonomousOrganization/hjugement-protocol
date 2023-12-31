{-# LANGUAGE OverloadedStrings #-}
module Election where

import Control.DeepSeq (NFData)
import qualified Data.List as List
import qualified Data.Text as Text
import qualified Text.Printf as Printf
import qualified Data.Aeson as JSON

import Voting.Protocol
import Utils

makeElection ::
 forall crypto v c.
 Reifies v Version =>
 CryptoParams crypto c =>
 Key crypto =>
 JSON.ToJSON crypto =>
 Int -> Int -> Election crypto v c
makeElection nQuests nChoices = elec
	where
	election_uuid = UUID "xLcs7ev6Jy6FHH"
	elec = Election
	 { election_name = Text.pack $ "elec"<>show nQuests<>show nChoices
	 , election_description = "benchmarkable election"
	 , election_uuid
	 , election_crypto = reflect (Proxy @c)
	 , election_public_key =
		let secKey = credentialSecretKey election_uuid (Credential "xLcs7ev6Jy6FHHE") in
		publicKey secKey
	 , election_hash = hashElection elec
	 , election_version = Just (reflect (Proxy @v))
	 , election_questions =
		(<$> [1..nQuests]) $ \quest -> Question
		 { question_text = Text.pack $ "quest"<>show quest
		 , question_choices = (<$> [1..nChoices]) $ \choice -> Text.pack $ "choice"<>show choice
		 , question_mini = one
		 , question_maxi = one -- sum $ List.replicate nChoices one
		 }
	 }

makeVotes :: Election crypto v c -> [[Bool]]
makeVotes Election{..} =
	[ True : List.tail [ False | _choice <- question_choices quest ]
	| quest <- election_questions
	]

makeBallot ::
 Reifies v Version =>
 CryptoParams crypto c => Key crypto =>
 Election crypto v c -> Ballot crypto v c
makeBallot elec =
	case runExcept $ (`evalStateT` mkStdGen seed) $ do
		ballotSecKey <- randomSecretKey
		encryptBallot elec (Just ballotSecKey) $
			makeVotes elec of
	 Right ballot -> ballot
	 Left err -> error ("encryptBallot: "<>show err)
	where
	seed = 0

titleElection :: Election crypto v c -> String
titleElection Election{..} =
	Printf.printf "(questions=%i)×(choices=%i)==%i"
	 nQuests nChoices (nQuests * nChoices)
	where
	nQuests  = List.length election_questions
	nChoices = List.foldr max 0 $ List.length . question_choices <$> election_questions

benchEncryptBallot ::
 forall crypto v c.
 CryptoParams crypto c =>
 Reifies v Version =>
 Key crypto =>
 JSON.ToJSON crypto =>
 NFData crypto =>
 Proxy v -> Proxy c -> Int -> Int -> Benchmark
benchEncryptBallot _v _c nQuests nChoices =
	let setupEnv = do
		let elec :: Election crypto v c = makeElection nQuests nChoices
		return elec in
	env setupEnv $ \ ~(elec) ->
		bench (titleElection elec) $
			nf makeBallot elec

benchVerifyBallot ::
 forall crypto v c.
 Reifies v Version =>
 CryptoParams crypto c =>
 Key crypto =>
 JSON.ToJSON crypto =>
 NFData crypto =>
 Proxy v -> Proxy c -> Int -> Int -> Benchmark
benchVerifyBallot (_v::Proxy v) (_c::Proxy c) nQuests nChoices =
	let setupEnv = do
		let elec :: Election crypto v c = makeElection nQuests nChoices
		let ballot = makeBallot elec
		return (elec,ballot) in
	env setupEnv $ \ ~(elec, ballot) ->
		bench (titleElection elec) $
			nf (verifyBallot elec) ballot

benchmarks :: [Benchmark]
benchmarks =
 [ benchsByVersion stableVersion
 -- , benchsByVersion experimentalVersion
 ]

benchsByVersion :: Version -> Benchmark
benchsByVersion version =
	reify version $ \v ->
	bgroup ("v"<>show version)
		[ benchsByCrypto v weakFFC
		, benchsByCrypto v beleniosFFC
		]

benchsByCrypto ::
 Reifies v Version =>
 ReifyCrypto crypto =>
 Key crypto =>
 JSON.ToJSON crypto =>
 NFData crypto =>
 Proxy v -> crypto -> Benchmark
benchsByCrypto v crypto =
	reifyCrypto crypto $ \c ->
	bgroup (Text.unpack (cryptoName crypto))
	 [ bgroup "encryptBallot"
		 [ benchEncryptBallot v c nQuests nChoices
		 | (nQuests,nChoices) <- inputs
		 ]
	 , bgroup "verifyBallot"
		 [ benchVerifyBallot v c nQuests nChoices
		 | (nQuests,nChoices) <- inputs
		 ]
	 ]
	where
	inputs =
		[ (nQ,nC)
		| nQ <- [1,5,10,15,20,25]
		, nC <- [5,7]
		]
