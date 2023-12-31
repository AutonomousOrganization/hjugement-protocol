{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies instances
module Voting.Protocol.Trustee.Indispensable where

import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), foldM, unless)
import Control.Monad.Trans.Except (ExceptT(..), throwE)
import Data.Aeson (ToJSON(..), FromJSON(..), (.:), (.=))
import Data.Eq (Eq(..))
import Data.Function (($))
import Data.Functor ((<$>))
import Data.Maybe (maybe)
import Data.Reflection (Reifies(..))
import Data.Semigroup (Semigroup(..))
import Data.Tuple (fst)
import GHC.Generics (Generic)
import System.Random (RandomGen)
import Text.Show (Show(..))
import qualified Control.Monad.Trans.State.Strict as S
import qualified Data.Aeson as JSON
import qualified Data.ByteString as BS
import qualified Data.List as List

import Voting.Protocol.Utils
import Voting.Protocol.Arithmetic
import Voting.Protocol.Version
import Voting.Protocol.Cryptography
import Voting.Protocol.Credential
import Voting.Protocol.Tally

-- * Type 'TrusteePublicKey'
data TrusteePublicKey crypto v c = TrusteePublicKey
 { trustee_PublicKey      :: !(PublicKey crypto c)
 , trustee_SecretKeyProof :: !(Proof crypto v c)
	-- ^ NOTE: It is important to ensure
	-- that each trustee generates its key pair independently
	-- of the 'PublicKey's published by the other trustees.
	-- Otherwise, a dishonest trustee could publish as 'PublicKey'
	-- its genuine 'PublicKey' divided by the 'PublicKey's of the other trustees.
	-- This would then lead to the 'election_PublicKey'
	-- being equal to this dishonest trustee's 'PublicKey',
	-- which means that knowing its 'SecretKey' would be sufficient
	-- for decrypting messages encrypted to the 'election_PublicKey'.
	-- To avoid this attack, each trustee publishing a 'PublicKey'
	-- must 'prove' knowledge of the corresponding 'SecretKey'.
	-- Which is done in 'proveIndispensableTrusteePublicKey'
	-- and 'verifyIndispensableTrusteePublicKey'.
 } deriving (Generic)
deriving instance Eq (G crypto c) => Eq (TrusteePublicKey crypto v c)
deriving instance (Show (G crypto c), Show (PublicKey crypto c)) => Show (TrusteePublicKey crypto v c)
deriving instance NFData (G crypto c) => NFData (TrusteePublicKey crypto v c)
instance
 ( Reifies v Version
 , ToJSON (G crypto c)
 ) => ToJSON (TrusteePublicKey crypto v c) where
	toJSON TrusteePublicKey{..} =
		JSON.object
		 [ "pok"        .= trustee_SecretKeyProof
		 , "public_key" .= trustee_PublicKey
		 ]
	toEncoding TrusteePublicKey{..} =
		JSON.pairs
		 (  "pok"        .= trustee_SecretKeyProof
		 <> "public_key" .= trustee_PublicKey
		 )
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (TrusteePublicKey crypto v c) where
	parseJSON = JSON.withObject "TrusteePublicKey" $ \o -> do
		trustee_PublicKey <- o .: "public_key"
		trustee_SecretKeyProof <- o .: "pok"
		return TrusteePublicKey{..}

-- ** Generating a 'TrusteePublicKey'

-- | @('proveIndispensableTrusteePublicKey' trustSecKey)@
-- returns the 'PublicKey' associated to 'trustSecKey'
-- and a 'Proof' of its knowledge.
proveIndispensableTrusteePublicKey ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Key crypto =>
 Monad m => RandomGen r =>
 SecretKey crypto c -> S.StateT r m (TrusteePublicKey crypto v c)
proveIndispensableTrusteePublicKey trustSecKey = do
	let trustee_PublicKey = publicKey trustSecKey
	trustee_SecretKeyProof <-
		prove trustSecKey [groupGen] $
			hash (indispensableTrusteePublicKeyStatement trustee_PublicKey)
	return TrusteePublicKey{..}

-- ** Checking a 'TrusteePublicKey' before incorporating it into the 'Election''s 'PublicKey'

-- | @('verifyIndispensableTrusteePublicKey' trustPubKey)@
-- returns 'True' iif. the given 'trustee_SecretKeyProof'
-- does 'prove' that the 'SecretKey' associated with
-- the given 'trustee_PublicKey' is known by the trustee.
verifyIndispensableTrusteePublicKey ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m =>
 TrusteePublicKey crypto v c ->
 ExceptT ErrorTrusteePublicKey m ()
verifyIndispensableTrusteePublicKey TrusteePublicKey{..} =
	unless (
		proof_challenge trustee_SecretKeyProof == hash
		 (indispensableTrusteePublicKeyStatement trustee_PublicKey)
		 [commit trustee_SecretKeyProof groupGen trustee_PublicKey]
	 ) $
		throwE ErrorTrusteePublicKey_WrongProof

-- ** Type 'ErrorTrusteePublicKey'
data ErrorTrusteePublicKey
 =   ErrorTrusteePublicKey_WrongProof
     -- ^ The 'trustee_SecretKeyProof' is wrong.
 deriving (Eq,Show)

-- ** Hashing
indispensableTrusteePublicKeyStatement ::
 CryptoParams crypto c =>
 PublicKey crypto c -> BS.ByteString
indispensableTrusteePublicKeyStatement trustPubKey =
	"pok|"<>bytesNat trustPubKey<>"|"

-- * 'Election''s 'PublicKey'

-- ** Generating an 'Election''s 'PublicKey' from multiple 'TrusteePublicKey's.

combineIndispensableTrusteePublicKeys ::
 CryptoParams crypto c =>
 [TrusteePublicKey crypto v c] -> PublicKey crypto c
combineIndispensableTrusteePublicKeys =
	List.foldr (\TrusteePublicKey{..} -> (trustee_PublicKey *)) one

-- ** Checking the trustee's 'DecryptionShare's before decrypting an 'EncryptedTally'.

verifyIndispensableDecryptionShareByTrustee ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m =>
 EncryptedTally crypto v c -> [PublicKey crypto c] -> [DecryptionShare crypto v c] ->
 ExceptT ErrorTally m ()
verifyIndispensableDecryptionShareByTrustee encByChoiceByQuest =
	isoZipWithM_ (throwE $ ErrorTally_NumberOfTrustees)
	 (verifyDecryptionShare encByChoiceByQuest)

-- ** Decrypting an 'EncryptedTally' from multiple 'TrusteePublicKey's.

-- | @('combineDecryptionShares' pubKeyByTrustee decShareByTrustee)@
-- returns the 'DecryptionFactor's by choice by 'Question'
combineIndispensableDecryptionShares ::
 Reifies v Version =>
 CryptoParams crypto c =>
 [PublicKey crypto c] -> DecryptionShareCombinator crypto v c
combineIndispensableDecryptionShares
 pubKeyByTrustee
 encByChoiceByQuest
 decByChoiceByQuestByTrustee = do
	verifyIndispensableDecryptionShareByTrustee
	 encByChoiceByQuest
	 pubKeyByTrustee
	 decByChoiceByQuestByTrustee
	(DecryptionShare dec0,decs) <-
		maybe (throwE ErrorTally_NumberOfTrustees) return $
		List.uncons decByChoiceByQuestByTrustee
	foldM (isoZipWithM (throwE ErrorTally_NumberOfQuestions)
	 (maybe (throwE ErrorTally_NumberOfChoices) return `o2`
		isoZipWith (\a (decFactor, _proof) -> a * decFactor)))
	 ((fst <$>) <$> dec0) (unDecryptionShare <$> decs)
