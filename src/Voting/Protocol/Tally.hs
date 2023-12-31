{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies instances
module Voting.Protocol.Tally where

import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), mapM, unless)
import Control.Monad.Trans.Except (Except, ExceptT, throwE)
import Data.Aeson (ToJSON(..), FromJSON(..), (.:), (.=))
import Data.Eq (Eq(..))
import Data.Function (($), (.))
import Data.Functor ((<$>))
import Data.Maybe (maybe)
import Data.Semigroup (Semigroup(..))
import Data.Reflection (Reifies(..))
import Data.Tuple (fst, snd)
import GHC.Generics (Generic)
import Numeric.Natural (Natural)
import System.Random (RandomGen)
import Text.Show (Show(..))
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import qualified Data.Aeson.Encoding as JSON
import qualified Control.Monad.Trans.State.Strict as S
import qualified Data.ByteString as BS
import qualified Data.List as List
import qualified Data.Map.Strict as Map

import Voting.Protocol.Utils
import Voting.Protocol.Arithmetic
import Voting.Protocol.Version
import Voting.Protocol.Cryptography
import Voting.Protocol.Credential
import Voting.Protocol.Election

-- * Type 'Tally'
data Tally crypto v c = Tally
 { tally_countMax :: !Natural
   -- ^ The maximal number of supportive 'Opinion's that a choice can get,
   -- which is here the same as the number of 'Ballot's.
   --
   -- Used in 'proveTally' to decrypt the actual
   -- count of votes obtained by a choice,
   -- by precomputing all powers of 'groupGen's up to it.
 , tally_encByChoiceByQuest :: !(EncryptedTally crypto v c)
   -- ^ 'Encryption' by 'Question' by 'Ballot'.
 , tally_decShareByTrustee :: ![DecryptionShare crypto v c]
   -- ^ 'DecryptionShare' by trustee.
 , tally_countByChoiceByQuest :: ![[Natural]]
   -- ^ The decrypted count of supportive 'Opinion's, by choice by 'Question'.
 } deriving (Generic)
deriving instance Eq (G crypto c) => Eq (Tally crypto v c)
deriving instance (Show (G crypto c), Show (G crypto c)) => Show (Tally crypto v c)
deriving instance NFData (G crypto c) => NFData (Tally crypto v c)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => ToJSON (Tally crypto v c) where
	toJSON Tally{..} =
		JSON.object
		 [ "num_tallied"         .= tally_countMax
		 , "encrypted_tally"     .= tally_encByChoiceByQuest
		 , "partial_decryptions" .= tally_decShareByTrustee
		 , "result"              .= tally_countByChoiceByQuest
		 ]
	toEncoding Tally{..} =
		JSON.pairs
		 (  "num_tallied"         .= tally_countMax
		 <> "encrypted_tally"     .= tally_encByChoiceByQuest
		 <> "partial_decryptions" .= tally_decShareByTrustee
		 <> "result"              .= tally_countByChoiceByQuest
		 )
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (Tally crypto v c) where
	parseJSON = JSON.withObject "Tally" $ \o -> do
		tally_countMax             <- o .: "num_tallied"
		tally_encByChoiceByQuest   <- o .: "encrypted_tally"
		tally_decShareByTrustee    <- o .: "partial_decryptions"
		tally_countByChoiceByQuest <- o .: "result"
		return Tally{..}

-- ** Type 'EncryptedTally'
-- | 'Encryption' by choice by 'Question'.
type EncryptedTally crypto v c = [[Encryption crypto v c]]

-- | @('encryptedTally' ballots)@
-- returns the sum of the 'Encryption's of the given @ballots@,
-- along with the number of 'Ballot's.
encryptedTally ::
 CryptoParams crypto c =>
 [Ballot crypto v c] -> (EncryptedTally crypto v c, Natural)
encryptedTally = List.foldr insertEncryptedTally emptyEncryptedTally

-- | The initial 'EncryptedTally' which tallies no 'Ballot'.
emptyEncryptedTally ::
 CryptoParams crypto c =>
 (EncryptedTally crypto v c, Natural)
emptyEncryptedTally = (List.repeat (List.repeat zero), 0)

-- | @('insertEncryptedTally' ballot encTally)@
-- returns the 'EncryptedTally' adding the votes of the given @(ballot)@
-- to those of the given @(encTally)@.
insertEncryptedTally ::
 CryptoParams crypto c =>
 Ballot crypto v c ->
 (EncryptedTally crypto v c, Natural) ->
 (EncryptedTally crypto v c, Natural)
insertEncryptedTally Ballot{..} (encTally, numBallots) =
	( List.zipWith
		 (\Answer{..} -> List.zipWith (+) (fst <$> answer_opinions))
		 ballot_answers
		 encTally
	, numBallots+1
	)

-- ** Type 'DecryptionShareCombinator'
type DecryptionShareCombinator crypto v c =
 EncryptedTally crypto v c ->
 [DecryptionShare crypto v c] ->
 Except ErrorTally [[DecryptionFactor crypto c]]

proveTally ::
 CryptoParams crypto c =>
 (EncryptedTally crypto v c, Natural) -> [DecryptionShare crypto v c] ->
 DecryptionShareCombinator crypto v c -> Except ErrorTally (Tally crypto v c)
proveTally
 (tally_encByChoiceByQuest, tally_countMax)
 tally_decShareByTrustee
 decShareCombinator = do
	decFactorByChoiceByQuest <-
		decShareCombinator
		 tally_encByChoiceByQuest
		 tally_decShareByTrustee
	dec <- isoZipWithM (throwE ErrorTally_NumberOfQuestions)
	 (maybe (throwE ErrorTally_NumberOfChoices) return `o2`
		isoZipWith (\Encryption{..} decFactor -> encryption_vault / decFactor))
	 tally_encByChoiceByQuest
	 decFactorByChoiceByQuest
	let logMap = Map.fromList $ List.zip groupGenPowers [0..tally_countMax]
	let log x =
		maybe (throwE ErrorTally_CannotDecryptCount) return $
		Map.lookup x logMap
	tally_countByChoiceByQuest <- (log `mapM`)`mapM`dec
	return Tally{..}

verifyTally ::
 CryptoParams crypto c =>
 Tally crypto v c ->
 DecryptionShareCombinator crypto v c ->
 Except ErrorTally ()
verifyTally Tally{..} decShareCombinator = do
	decFactorByChoiceByQuest <- decShareCombinator tally_encByChoiceByQuest tally_decShareByTrustee
	isoZipWith3M_ (throwE ErrorTally_NumberOfQuestions)
	 (isoZipWith3M_ (throwE ErrorTally_NumberOfChoices)
		 (\Encryption{..} decFactor count -> do
			let groupGenPowCount = encryption_vault / decFactor
			unless (groupGenPowCount == groupGen ^ fromNatural count) $
				throwE ErrorTally_WrongProof))
	 tally_encByChoiceByQuest
	 decFactorByChoiceByQuest
	 tally_countByChoiceByQuest

-- ** Type 'DecryptionShare'
-- | A decryption share is a 'DecryptionFactor' and a decryption 'Proof', by choice by 'Question'.
-- Computed by a trustee in 'proveDecryptionShare'.
newtype DecryptionShare crypto v c = DecryptionShare
 { unDecryptionShare :: [[(DecryptionFactor crypto c, Proof crypto v c)]] }
 deriving (Generic)
deriving instance Eq (G crypto c) => Eq (DecryptionShare crypto v c)
deriving instance Show (G crypto c) => Show (DecryptionShare crypto v c)
deriving newtype instance NFData (G crypto c) => NFData (DecryptionShare crypto v c)
instance
 ( Reifies v Version
 , ToJSON (G crypto c)
 ) => ToJSON (DecryptionShare crypto v c) where
	toJSON (DecryptionShare decByChoiceByQuest) =
		JSON.object
		 [ "decryption_factors" .=
			toJSONList (((toJSON . fst) <$>) <$> decByChoiceByQuest)
		 , "decryption_proofs" .=
			toJSONList (((toJSON . snd) <$>) <$> decByChoiceByQuest)
		 ]
	toEncoding (DecryptionShare decByChoiceByQuest) =
		JSON.pairs $
			JSON.pair "decryption_factors"
			 (JSON.list (JSON.list (toEncoding . fst)) decByChoiceByQuest) <>
			JSON.pair "decryption_proofs"
			 (JSON.list (JSON.list (toEncoding . snd)) decByChoiceByQuest)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (DecryptionShare crypto v c) where
	parseJSON = JSON.withObject "DecryptionShare" $ \o -> do
		decFactors <- o .: "decryption_factors"
		decProofs  <- o .: "decryption_proofs"
		let err msg = JSON.typeMismatch ("DecryptionShare: "<>msg) (JSON.Object o)
		DecryptionShare
		 <$> isoZipWithM (err "inconsistent number of questions")
			 (isoZipWithM (err "inconsistent number of choices")
				 (\a b -> return (a, b)))
		 decFactors decProofs

-- *** Type 'DecryptionFactor'
-- | @'encryption_nonce' '^'trusteeSecKey@
type DecryptionFactor = G

-- @('proveDecryptionShare' encByChoiceByQuest trusteeSecKey)@
proveDecryptionShare ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Key crypto =>
 Monad m => RandomGen r =>
 EncryptedTally crypto v c -> SecretKey crypto c -> S.StateT r m (DecryptionShare crypto v c)
proveDecryptionShare encByChoiceByQuest trusteeSecKey =
	(DecryptionShare <$>) $
	(proveDecryptionFactor trusteeSecKey `mapM`) `mapM` encByChoiceByQuest

proveDecryptionFactor ::
 Reifies v Version => 
 CryptoParams crypto c =>
 Key crypto =>
 Monad m => RandomGen r =>
 SecretKey crypto c -> Encryption crypto v c -> S.StateT r m (DecryptionFactor crypto c, Proof crypto v c)
proveDecryptionFactor trusteeSecKey Encryption{..} = do
	proof <- prove trusteeSecKey [groupGen, encryption_nonce] (hash zkp)
	return (encryption_nonce^trusteeSecKey, proof)
	where zkp = decryptionShareStatement (publicKey trusteeSecKey)

decryptionShareStatement :: CryptoParams crypto c => PublicKey crypto c -> BS.ByteString
decryptionShareStatement pubKey =
	"decrypt|"<>bytesNat pubKey<>"|"

-- *** Type 'ErrorTally'
data ErrorTally
 =   ErrorTally_NumberOfQuestions
     -- ^ The number of 'Question's is not the one expected.
 |   ErrorTally_NumberOfChoices
     -- ^ The number of choices is not the one expected.
 |   ErrorTally_NumberOfTrustees
     -- ^ The number of trustees is not the one expected.
 |   ErrorTally_WrongProof
     -- ^ The 'Proof' of a 'DecryptionFactor' is wrong.
 |   ErrorTally_CannotDecryptCount
     -- ^ Raised by 'proveTally' when the discrete logarithm of @'groupGen' '^'count@
     -- cannot be computed, likely because 'tally_countMax' is wrong,
     -- or because the 'EncryptedTally' or 'DecryptionShare's have not been verified.
 deriving (Eq,Show,Generic,NFData)

-- | @('verifyDecryptionShare' encTally trusteePubKey trusteeDecShare)@
-- checks that 'trusteeDecShare'
-- (supposedly submitted by a trustee whose 'PublicKey' is 'trusteePubKey')
-- is valid with respect to the 'EncryptedTally' 'encTally'.
verifyDecryptionShare ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m =>
 EncryptedTally crypto v c -> PublicKey crypto c -> DecryptionShare crypto v c ->
 ExceptT ErrorTally m ()
verifyDecryptionShare encByChoiceByQuest trusteePubKey (DecryptionShare decShare) =
	let zkp = decryptionShareStatement trusteePubKey in
	isoZipWithM_ (throwE ErrorTally_NumberOfQuestions)
	 (isoZipWithM_ (throwE ErrorTally_NumberOfChoices) $
	 \Encryption{..} (decFactor, proof) ->
		unless (proof_challenge proof == hash zkp
		 [ commit proof groupGen trusteePubKey
		 , commit proof encryption_nonce decFactor
		 ]) $ throwE ErrorTally_WrongProof)
	 encByChoiceByQuest
	 decShare

verifyDecryptionShareByTrustee ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m =>
 EncryptedTally crypto v c -> [PublicKey crypto c] -> [DecryptionShare crypto v c] ->
 ExceptT ErrorTally m ()
verifyDecryptionShareByTrustee encTally =
	isoZipWithM_ (throwE ErrorTally_NumberOfTrustees)
	 (verifyDecryptionShare encTally)
