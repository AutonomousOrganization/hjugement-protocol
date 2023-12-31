{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies instances
{-# OPTIONS -fno-warn-orphans #-}
module QuickCheck.Election where

import Data.Eq (Eq(..))
import Data.Int (Int)
import Data.Maybe (fromJust)
import Data.Ord (Ord(..))
import GHC.Natural (minusNaturalMaybe)
import Prelude (undefined)
import Test.Tasty.QuickCheck
import qualified Data.Aeson as JSON
import qualified Data.List as List
import qualified Data.Text as Text

import Voting.Protocol

import Utils

-- Hardcoded limits to avoid keep a reasonable testing time.
maxArbitraryChoices :: Natural
maxArbitraryChoices = 5
maxArbitraryQuestions :: Natural
maxArbitraryQuestions = 2

quickcheck :: Reifies v Version => Proxy v -> TestTree
quickcheck v =
	testGroup "Election"
	 [ testGroup "verifyBallot" $ 
		 [ reify weakFFC $ quickcheckElection v
		 , reify beleniosFFC $ quickcheckElection v
		 ]
	 ]

quickcheckElection ::
 Reifies v Version => 
 CryptoParams crypto c =>
 Key crypto => JSON.ToJSON crypto => Show crypto =>
 Proxy v -> Proxy c -> TestTree
quickcheckElection (_v::Proxy v) (c::Proxy c) =
	testGroup (Text.unpack $ cryptoName (reflect c))
	 [ testProperty "verifyBallot" $ \(seed, (elec::Election crypto v c) :> votes) ->
		isRight $ runExcept $
			(`evalStateT` mkStdGen seed) $ do
				-- ballotSecKey :: SecretKey c <- randomSecretKey
				ballot <- encryptBallot elec Nothing votes
				unless (verifyBallot elec ballot) $
					lift $ throwE $ ErrorBallot_Wrong
	 ]

{-
instance Reifies c FFC => Arbitrary (F c) where
	arbitrary = F <$> choose (zero, fromJust $ fieldCharac @c `minusNaturalMaybe` one)
-}
instance CryptoParams crypto c => Arbitrary (G crypto c) where
	arbitrary = do
		m <- arbitrary
		return (groupGen ^ m)
instance CryptoParams crypto c => Arbitrary (E crypto c) where
	arbitrary = E <$> choose (zero, fromJust $ groupOrder @crypto (Proxy @c) `minusNaturalMaybe` one)
instance Arbitrary UUID where
	arbitrary = do
		seed <- arbitrary
		(`evalStateT` mkStdGen seed) $
			randomUUID
instance
 ( Reifies v Version
 , CryptoParams crypto c
 , Arbitrary (E crypto c)
 ) => Arbitrary (Proof crypto v c) where
	arbitrary = do
		proof_challenge <- arbitrary
		proof_response  <- arbitrary
		return Proof{..}
instance Reifies v Version => Arbitrary (Question v) where
	arbitrary = do
		let question_text = "question"
		choices :: Natural <- choose (1, maxArbitraryChoices)
		let question_choices = [Text.pack ("c"<>show c) | c <- [1..choices]]
		question_mini <- choose (0, choices)
		question_maxi <- choose (nat question_mini, choices)
		return Question{..}
	shrink quest =
		[ quest{question_choices, question_mini, question_maxi}
		| question_choices <- shrinkList pure $ question_choices quest
		, let nChoices = fromIntegral $ List.length question_choices
		, question_mini <- shrinkIntegral $ min nChoices $ max zero $ question_mini quest
		, question_maxi <- shrinkIntegral $ min nChoices $ max question_mini $ question_maxi quest
		]
instance
 ( Reifies v Version
 , CryptoParams crypto c
 , Key crypto
 , JSON.ToJSON crypto
 ) => Arbitrary (Election crypto v c) where
	arbitrary = do
		let election_name = "election"
		let election_description = "description"
		let election_crypto = reflect (Proxy @c)
		election_secret_key <- arbitrary
		let election_public_key = publicKey election_secret_key
		election_questions <- resize (fromIntegral maxArbitraryQuestions) $ listOf1 arbitrary
		election_uuid <- arbitrary
		let elec = Election
			 { election_hash    = hashElection elec
			 , election_version = Just (reflect (Proxy @v))
			 , ..
			 }
		return elec
	shrink elec =
		[ elec{election_questions}
		| election_questions <- shrink $ election_questions elec
		]
{-
instance Reifies c FFC => Arbitrary (ElectionCrypto c) where
	arbitrary = do
		let electionCrypto_FFC_params = reflect (Proxy::Proxy c)
		electionCrypto_FFC_PublicKey <- arbitrary
		return ElectionCrypto_FFC{..}
-}

-- | A type to declare an 'Arbitrary' instance where @b@ depends on @a@.
data (:>) a b = a :> b
 deriving (Eq,Show)
instance Reifies v Version => Arbitrary (Question v :> [Bool]) where
	arbitrary = do
		quest@Question{..} <- arbitrary
		votes <- do
			let numChoices = List.length question_choices
			numTrue <- fromIntegral <$> choose (nat question_mini, nat question_maxi)
			rank <- choose (0, nCk numChoices numTrue - 1)
			return $ boolsOfCombin numChoices numTrue rank
		return (quest :> votes)
	shrink (quest :> votes) =
		[ q :> shrinkVotes q votes
		| q <- shrink quest
		]
instance
 ( Reifies v Version
 , CryptoParams crypto c
 , Key crypto
 , JSON.ToJSON crypto
 ) => Arbitrary (Election crypto v c :> [[Bool]]) where
	arbitrary = do
		elec@Election{..} <- arbitrary
		votes <- forM election_questions $ \Question{..} -> do
			let numChoices = List.length question_choices
			numTrue <- fromIntegral <$> choose (nat question_mini, nat question_maxi)
			rank <- choose (0, nCk numChoices numTrue - 1)
			return $ boolsOfCombin numChoices numTrue rank
		return (elec :> votes)
	shrink (elec :> votes) =
		[ e :> List.zipWith shrinkVotes (election_questions e :: [Question v]) votes
		| e <- shrink elec
		]

-- | @('boolsOfCombin' nBits nTrue rank)@ returns the 'rank'-th sequence of 'nBits'-bits possible
-- with 'nTrue' bits set at 'True' and @(nBits-nTrue)@ set at 'False'.
-- @rank@ has to be in @[0 .. 'nCk' nBits nTrue '-' 1]@
boolsOfCombin :: Int -> Int -> Int -> [Bool]
boolsOfCombin nBits nTrue rank
 | rank < 0 = undefined
 | nTrue == 0 = List.replicate nBits False
 | otherwise = go 0 cs <> List.replicate (nBits-List.last cs) False
	where
	cs = combinOfRank nBits nTrue rank
	go _d [] = []
	go curr (next:ns) =
		List.replicate (next-1-curr) False <> [True]
		 <> go next ns

-- | @('shrinkVotes' quest votes)@
-- returns a reduced version of the given @votes@
-- to fit the requirement of the given @quest@.
shrinkVotes :: Reifies v Version => Question v -> [Bool] -> [Bool]
shrinkVotes Question{..} votes =
	(\(nTrue, b) -> nTrue <= nat question_maxi && b)
	 <$> List.zip (countTrue votes) votes
	where
	countTrue :: [Bool] -> [Natural]
	countTrue = List.foldl' (\ns b -> if b then inc ns else ns) []
		where
		inc [] = [zero]
		inc (n:ns) = (n+one):n:ns
