{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE Rank2Types #-} -- for readElection
{-# LANGUAGE UndecidableInstances #-} -- for Reifies constraints in instances
module Voting.Protocol.Election where

import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), mapM, zipWithM)
import Control.Monad.Trans.Class (MonadTrans(..))
import Control.Monad.Trans.Except (ExceptT(..), runExcept, throwE, withExceptT)
import Data.Aeson (ToJSON(..),FromJSON(..),(.:),(.:?),(.=))
import Data.Bool
import Data.Either (either)
import Data.Eq (Eq(..))
import Data.Foldable (foldMap, and)
import Data.Function (($), (.), id, const)
import Data.Functor ((<$>))
import Data.Functor.Identity (Identity(..))
import Data.Maybe (Maybe(..), maybe, fromJust, fromMaybe)
import Data.Monoid (Monoid(..))
import Data.Ord (Ord(..))
import Data.Proxy (Proxy(..))
import Data.Reflection (Reifies(..), reify)
import Data.Semigroup (Semigroup(..))
import Data.String (String)
import Data.Text (Text)
import Data.Traversable (Traversable(..))
import Data.Tuple (fst, snd)
import GHC.Generics (Generic)
import GHC.Natural (minusNaturalMaybe)
import Numeric.Natural (Natural)
import Prelude (fromIntegral)
import System.IO (IO, FilePath)
import System.Random (RandomGen)
import Text.Show (Show(..))
import qualified Control.Monad.Trans.State.Strict as S
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Encoding as JSON
import qualified Data.Aeson.Internal as JSON
import qualified Data.Aeson.Parser.Internal as JSON
import qualified Data.Aeson.Types as JSON
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.List as List

import Voting.Protocol.Utils
import Voting.Protocol.Arithmetic
import Voting.Protocol.Version
import Voting.Protocol.Credential
import Voting.Protocol.Cryptography

-- * Type 'Question'
data Question v = Question
 { question_text    :: !Text
 , question_choices :: ![Text]
 , question_mini    :: !Natural
 , question_maxi    :: !Natural
 -- , question_blank :: Maybe Bool
 } deriving (Eq,Show,Generic,NFData)
instance Reifies v Version => ToJSON (Question v) where
	toJSON Question{..} =
		JSON.object
		 [ "question" .= question_text
		 , "answers"  .= question_choices
		 , "min"      .= question_mini
		 , "max"      .= question_maxi
		 ]
	toEncoding Question{..} =
		JSON.pairs
		 (  "question" .= question_text
		 <> "answers"  .= question_choices
		 <> "min"      .= question_mini
		 <> "max"      .= question_maxi
		 )
instance Reifies v Version => FromJSON (Question v) where
	parseJSON = JSON.withObject "Question" $ \o -> do
		question_text    <- o .: "question"
		question_choices <- o .: "answers"
		question_mini    <- o .: "min"
		question_maxi    <- o .: "max"
		return Question{..}

-- * Type 'Answer'
data Answer crypto v c = Answer
 { answer_opinions :: ![(Encryption crypto v c, DisjProof crypto v c)]
   -- ^ Encrypted 'Opinion' for each 'question_choices'
   -- with a 'DisjProof' that they belong to [0,1].
 , answer_sumProof :: !(DisjProof crypto v c)
   -- ^ Proofs that the sum of the 'Opinon's encrypted in 'answer_opinions'
   -- is an element of @[mini..maxi]@.
 -- , answer_blankProof ::
 } deriving (Generic)
deriving instance Eq (G crypto c) => Eq (Answer crypto v c)
deriving instance (Show (G crypto c), Show (G crypto c)) => Show (Answer crypto v c)
deriving instance NFData (G crypto c) => NFData (Answer crypto v c)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => ToJSON (Answer crypto v c) where
	toJSON Answer{..} =
		let (answer_choices, answer_individual_proofs) =
			List.unzip answer_opinions in
		JSON.object
		 [ "choices"           .= answer_choices
		 , "individual_proofs" .= answer_individual_proofs
		 , "overall_proof"     .= answer_sumProof
		 ]
	toEncoding Answer{..} =
		let (answer_choices, answer_individual_proofs) =
			List.unzip answer_opinions in
		JSON.pairs
		 (  "choices"           .= answer_choices
		 <> "individual_proofs" .= answer_individual_proofs
		 <> "overall_proof"     .= answer_sumProof
		 )
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (Answer crypto v c) where
	parseJSON = JSON.withObject "Answer" $ \o -> do
		answer_choices <- o .: "choices"
		answer_individual_proofs <- o .: "individual_proofs"
		let answer_opinions = List.zip answer_choices answer_individual_proofs
		answer_sumProof <- o .: "overall_proof"
		return Answer{..}

-- | @('encryptAnswer' elecPubKey zkp quest opinions)@
-- returns an 'Answer' validable by 'verifyAnswer',
-- unless an 'ErrorAnswer' is returned.
encryptAnswer ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m => RandomGen r =>
 PublicKey crypto c -> ZKP ->
 Question v -> [Bool] ->
 S.StateT r (ExceptT ErrorAnswer m) (Answer crypto v c)
encryptAnswer (elecPubKey::PublicKey crypto c) zkp Question{..} opinionByChoice
 | not (question_mini <= opinionsSum && opinionsSum <= question_maxi) =
	lift $ throwE $
		ErrorAnswer_WrongSumOfOpinions opinionsSum question_mini question_maxi
 | List.length opinions /= List.length question_choices =
	lift $ throwE $
		ErrorAnswer_WrongNumberOfOpinions
		 (fromIntegral $ List.length opinions)
		 (fromIntegral $ List.length question_choices)
 | otherwise = do
	encryptions <- encrypt elecPubKey `mapM` opinions
	individualProofs <- zipWithM
	 (\opinion -> proveEncryption elecPubKey zkp $
		if opinion
		then (List.init booleanDisjunctions,[])
		else ([],List.tail booleanDisjunctions))
	 opinionByChoice encryptions
	sumProof <- proveEncryption elecPubKey zkp
	 (List.tail <$> List.genericSplitAt
		 (fromJust $ opinionsSum`minusNaturalMaybe`question_mini)
		 (intervalDisjunctions question_mini question_maxi))
	 ( sum (fst <$> encryptions) -- NOTE: sum the 'encNonce's
	 , sum (snd <$> encryptions) -- NOTE: sum the 'Encryption's
	 )
	return $ Answer
	 { answer_opinions = List.zip
		 (snd <$> encryptions) -- NOTE: drop encNonce
		 individualProofs
	 , answer_sumProof = sumProof
	 }
 where
	opinionsSum = sum $ nat <$> opinions
	opinions = (\o -> if o then one else zero) <$> opinionByChoice

verifyAnswer ::
 Reifies v Version =>
 CryptoParams crypto c =>
 PublicKey crypto c -> ZKP ->
 Question v -> Answer crypto v c -> Bool
verifyAnswer (elecPubKey::PublicKey crypto c) zkp Question{..} Answer{..}
 | List.length question_choices /= List.length answer_opinions = False
 | otherwise = do
	either (const False) id $ runExcept $ do
		validOpinions <-
			verifyEncryption elecPubKey zkp booleanDisjunctions
			 `traverse` answer_opinions
		validSum <- verifyEncryption elecPubKey zkp
		 (intervalDisjunctions question_mini question_maxi)
		 ( sum (fst <$> answer_opinions)
		 , answer_sumProof )
		return (and validOpinions && validSum)

-- ** Type 'ErrorAnswer'
-- | Error raised by 'encryptAnswer'.
data ErrorAnswer
 =   ErrorAnswer_WrongNumberOfOpinions Natural Natural
     -- ^ When the number of opinions is different than
     -- the number of choices ('question_choices').
 |   ErrorAnswer_WrongSumOfOpinions Natural Natural Natural
     -- ^ When the sum of opinions is not within the bounds
     -- of 'question_mini' and 'question_maxi'.
 deriving (Eq,Show,Generic,NFData)

-- ** Type 'Opinion'
-- | Index of a 'Disjunction' within a list of them.
-- It is encrypted as a 'GroupExponent' by 'encrypt'.
type Opinion = E

-- * Type 'Election'
data Election crypto v c = Election
 { election_name        :: !Text
 , election_description :: !Text
 , election_questions   :: ![Question v]
 , election_uuid        :: !UUID
 , election_hash        :: Base64SHA256
 , election_crypto      :: !crypto
 , election_version     :: !(Maybe Version)
 , election_public_key  :: !(PublicKey crypto c)
 } deriving (Generic)
deriving instance (Eq crypto, Eq (G crypto c)) => Eq (Election crypto v c)
deriving instance (Show crypto, Show (G crypto c)) => Show (Election crypto v c)
deriving instance (NFData crypto, NFData (G crypto c)) => NFData (Election crypto v c)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 , ToJSON crypto
 ) => ToJSON (Election crypto v c) where
	toJSON Election{..} =
		JSON.object $
		 [ "name" .= election_name
		 , "description" .= election_description
		 , ("public_key", JSON.object
			 [ "group" .= election_crypto
			 , "y" .= election_public_key
			 ])
		 , "questions" .= election_questions
		 , "uuid" .= election_uuid
		 ] <>
		 maybe [] (\version -> [ "version" .= version ]) election_version
	toEncoding Election{..} =
		JSON.pairs $
		 (  "name" .= election_name
		 <> "description" .= election_description
		 <> JSON.pair "public_key" (JSON.pairs $
			"group" .= election_crypto
			<> "y" .= election_public_key
		 )
		 <> "questions" .= election_questions
		 <> "uuid" .= election_uuid
		 ) <>
		 maybe mempty ("version" .=) election_version

hashElection ::
 Reifies v Version =>
 CryptoParams crypto c =>
 ToJSON crypto =>
 Election crypto v c -> Base64SHA256
hashElection = base64SHA256 . BSL.toStrict . JSON.encode

readElection ::
 forall crypto r.
 FromJSON crypto =>
 ReifyCrypto crypto =>
 FilePath ->
 (forall v c.
	Reifies v Version =>
	CryptoParams crypto c =>
	Election crypto v c -> r) ->
 ExceptT String IO r
readElection filePath k = do
	fileData <- lift $ BS.readFile filePath
	ExceptT $ return $
		jsonEitherFormatError $
			JSON.eitherDecodeStrictWith JSON.jsonEOF
			 (JSON.iparse (parseElection fileData))
			 fileData
	where
	parseElection fileData = JSON.withObject "Election" $ \o -> do
		election_version <- o .:? "version"
		reify (fromMaybe stableVersion election_version) $ \(_v::Proxy v) -> do
			(election_crypto, elecPubKey) <-
				JSON.explicitParseField
				 (JSON.withObject "public_key" $ \obj -> do
						crypto <- obj .: "group"
						pubKey :: JSON.Value <- obj .: "y"
						return (crypto, pubKey)
				 ) o "public_key"
			reifyCrypto election_crypto $ \(_c::Proxy c) -> do
				election_name <- o .: "name"
				election_description <- o .: "description"
				election_questions <- o .: "questions" :: JSON.Parser [Question v]
				election_uuid <- o .: "uuid"
				election_public_key :: PublicKey crypto c <- parseJSON elecPubKey
				return $ k $ Election
				 { election_questions  = election_questions
				 , election_public_key = election_public_key
				 , election_hash       = base64SHA256 fileData
				 , ..
				 }

-- * Type 'Ballot'
data Ballot crypto v c = Ballot
 { ballot_answers       :: ![Answer crypto v c]
 , ballot_signature     :: !(Maybe (Signature crypto v c))
 , ballot_election_uuid :: !UUID
 , ballot_election_hash :: !Base64SHA256
 } deriving (Generic)
deriving instance (NFData (G crypto c), NFData crypto) => NFData (Ballot crypto v c)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 , ToJSON (G crypto c)
 ) => ToJSON (Ballot crypto v c) where
	toJSON Ballot{..} =
		JSON.object $
		 [ "answers"       .= ballot_answers
		 , "election_uuid" .= ballot_election_uuid
		 , "election_hash" .= ballot_election_hash
		 ] <>
		 maybe [] (\sig -> [ "signature" .= sig ]) ballot_signature
	toEncoding Ballot{..} =
		JSON.pairs $
		 (  "answers"       .= ballot_answers
		 <> "election_uuid" .= ballot_election_uuid
		 <> "election_hash" .= ballot_election_hash
		 ) <>
		 maybe mempty ("signature" .=) ballot_signature
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (Ballot crypto v c) where
	parseJSON = JSON.withObject "Ballot" $ \o -> do
		ballot_answers       <- o .: "answers"
		ballot_signature     <- o .:? "signature"
		ballot_election_uuid <- o .: "election_uuid"
		ballot_election_hash <- o .: "election_hash"
		return Ballot{..}

-- | @('encryptBallot' c ('Just' ballotSecKey) opinionsByQuest)@
-- returns a 'Ballot' signed by 'secKey' (the voter's secret key)
-- where 'opinionsByQuest' is a list of 'Opinion's
-- on each 'question_choices' of each 'election_questions'.
encryptBallot ::
 Reifies v Version =>
 CryptoParams crypto c => Key crypto =>
 Monad m => RandomGen r =>
 Election crypto v c ->
 Maybe (SecretKey crypto c) -> [[Bool]] ->
 S.StateT r (ExceptT ErrorBallot m) (Ballot crypto v c)
encryptBallot (Election{..}::Election crypto v c) ballotSecKeyMay opinionsByQuest
 | List.length election_questions /= List.length opinionsByQuest =
	lift $ throwE $
		ErrorBallot_WrongNumberOfAnswers
		 (fromIntegral $ List.length opinionsByQuest)
		 (fromIntegral $ List.length election_questions)
 | otherwise = do
	let (voterKeys, voterZKP) =
		case ballotSecKeyMay of
		 Nothing -> (Nothing, ZKP "")
		 Just ballotSecKey ->
			( Just (ballotSecKey, ballotPubKey)
			, ZKP (bytesNat ballotPubKey) )
			where ballotPubKey = publicKey ballotSecKey
	ballot_answers <-
		S.mapStateT (withExceptT ErrorBallot_Answer) $
			zipWithM (encryptAnswer election_public_key voterZKP)
			 election_questions opinionsByQuest
	ballot_signature <- case voterKeys of
	 Nothing -> return Nothing
	 Just (ballotSecKey, signature_publicKey) -> do
		signature_proof <-
			proveQuicker ballotSecKey (Identity groupGen) $
			 \(Identity commitment) ->
				hash @crypto
				 -- NOTE: the order is unusual, the commitments are first
				 -- then comes the statement. Best guess is that
				 -- this is easier to code due to their respective types.
				 (ballotCommitments @crypto voterZKP commitment)
				 (ballotStatement @crypto ballot_answers)
		return $ Just Signature{..}
	return Ballot
	 { ballot_answers
	 , ballot_election_hash = election_hash
	 , ballot_election_uuid = election_uuid
	 , ballot_signature
	 }

verifyBallot ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Election crypto v c ->
 Ballot crypto v c -> Bool
verifyBallot (Election{..}::Election crypto v c) Ballot{..} =
	ballot_election_uuid == election_uuid &&
	ballot_election_hash == election_hash &&
	List.length election_questions == List.length ballot_answers &&
	let (isValidSign, zkpSign) =
		case ballot_signature of
		 Nothing -> (True, ZKP "")
		 Just Signature{..} ->
			let zkp = ZKP (bytesNat signature_publicKey) in
			(, zkp) $
				proof_challenge signature_proof == hash
				 (ballotCommitments @crypto zkp (commitQuicker signature_proof groupGen signature_publicKey))
				 (ballotStatement @crypto ballot_answers)
	in
	and $ isValidSign :
		List.zipWith (verifyAnswer election_public_key zkpSign)
		 election_questions ballot_answers


-- ** Type 'ErrorBallot'
-- | Error raised by 'encryptBallot'.
data ErrorBallot
 =   ErrorBallot_WrongNumberOfAnswers Natural Natural
     -- ^ When the number of answers
     -- is different than the number of questions.
 |   ErrorBallot_Answer ErrorAnswer
     -- ^ When 'encryptAnswer' raised an 'ErrorAnswer'.
 |   ErrorBallot_Wrong
     -- ^ TODO: to be more precise.
 deriving (Eq,Show,Generic,NFData)

-- ** Hashing

-- | @('ballotStatement' ballot)@
-- returns the encrypted material to be signed:
-- all the 'encryption_nonce's and 'encryption_vault's of the given 'ballot_answers'.
ballotStatement :: CryptoParams crypto c => [Answer crypto v c] -> [G crypto c]
ballotStatement =
	foldMap $ \Answer{..} ->
		(`foldMap` answer_opinions) $ \(Encryption{..}, _proof) ->
			[encryption_nonce, encryption_vault]

-- | @('ballotCommitments' voterZKP commitment)@
ballotCommitments ::
 CryptoParams crypto c =>
 ToNatural (G crypto c) =>
 ZKP -> Commitment crypto c -> BS.ByteString
ballotCommitments (ZKP voterZKP) commitment =
	"sig|"<>voterZKP<>"|" -- NOTE: this is actually part of the statement
	 <> bytesNat commitment<>"|"
