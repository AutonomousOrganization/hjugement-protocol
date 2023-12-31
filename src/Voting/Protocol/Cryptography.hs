{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies constraints in instances
module Voting.Protocol.Cryptography where

import Control.DeepSeq (NFData)
import Control.Monad (Monad(..), join, replicateM)
import Control.Monad.Trans.Except (ExceptT(..), throwE)
import Data.Aeson (ToJSON(..), FromJSON(..), (.:), (.=))
import Data.Bits
import Data.Bool
import Data.Eq (Eq(..))
import Data.Function (($), (.))
import Data.Functor (Functor, (<$>))
import Data.Maybe (Maybe(..), fromJust)
import Data.Ord (Ord(..))
import Data.Proxy (Proxy(..))
import Data.Reflection (Reifies(..))
import Data.Semigroup (Semigroup(..))
import Data.String (IsString(..))
import Data.Text (Text)
import GHC.Generics (Generic)
import GHC.Natural (minusNaturalMaybe)
import Numeric.Natural (Natural)
import Prelude (Bounded(..), fromIntegral)
import System.Random (RandomGen)
import Text.Show (Show(..))
import qualified Control.Monad.Trans.State.Strict as S
import qualified Crypto.Hash as Crypto
import qualified Data.Aeson as JSON
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as BS64
import qualified Data.List as List
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Builder as TLB
import qualified Data.Text.Lazy.Builder.Int as TLB
import qualified System.Random as Random

import Voting.Protocol.Utils
import Voting.Protocol.Arithmetic
import Voting.Protocol.Version

-- ** Type 'PublicKey'
type PublicKey = G
-- ** Type 'SecretKey'
type SecretKey = E

-- * Type 'Hash'
newtype Hash crypto c = Hash (E crypto c)
 deriving newtype (Eq,Ord,Show,NFData)

-- | @('hash' bs gs)@ returns as a number in 'E'
-- the 'Crypto.SHA256' hash of the given 'BS.ByteString' 'bs'
-- prefixing the decimal representation of given subgroup elements 'gs',
-- with a comma (",") intercalated between them.
--
-- NOTE: to avoid any collision when the 'hash' function is used in different contexts,
-- a message 'gs' is actually prefixed by a 'bs' indicating the context.
--
-- Used by 'proveEncryption' and 'verifyEncryption',
-- where the 'bs' usually contains the 'statement' to be proven,
-- and the 'gs' contains the 'commitments'.
hash :: CryptoParams crypto c => BS.ByteString -> [G crypto c] -> E crypto c
hash bs gs = do
	let s = bs <> BS.intercalate (fromString ",") (bytesNat <$> gs)
	let h = Crypto.hashWith Crypto.SHA256 s
	fromNatural $
		decodeBigEndian $ ByteArray.convert h

-- | @('decodeBigEndian' bs)@ interpret @bs@ as big-endian number.
decodeBigEndian :: BS.ByteString -> Natural
decodeBigEndian =
	BS.foldl'
	 (\acc b -> acc`shiftL`8 + fromIntegral b)
	 (0::Natural)

-- ** Type 'Base64SHA256'
newtype Base64SHA256 = Base64SHA256 Text
 deriving (Eq,Ord,Show,Generic)
 deriving anyclass (ToJSON,FromJSON)
 deriving newtype NFData

-- | @('base64SHA256' bs)@ returns the 'Crypto.SHA256' hash
-- of the given 'BS.ByteString' 'bs',
-- as a 'Text' escaped in @base64@ encoding
-- (<https://tools.ietf.org/html/rfc4648 RFC 4648>).
base64SHA256 :: BS.ByteString -> Base64SHA256
base64SHA256 bs =
	let h = Crypto.hashWith Crypto.SHA256 bs in
	Base64SHA256 $
		Text.takeWhile (/= '=') $ -- NOTE: no padding.
		Text.decodeUtf8 $ BS64.encode $ ByteArray.convert h

-- ** Type 'HexSHA256'
newtype HexSHA256 = HexSHA256 Text
 deriving (Eq,Ord,Show,Generic)
 deriving anyclass (ToJSON,FromJSON)
 deriving newtype NFData
-- | @('hexSHA256' bs)@ returns the 'Crypto.SHA256' hash
-- of the given 'BS.ByteString' 'bs', escaped in hexadecimal
-- into a 'Text' of 32 lowercase characters.
--
-- Used (in retro-dependencies of this library) to hash
-- the 'PublicKey' of a voter or a trustee.
hexSHA256 :: BS.ByteString -> Text
hexSHA256 bs =
	let h = Crypto.hashWith Crypto.SHA256 bs in
	let n = decodeBigEndian $ ByteArray.convert h in
	-- NOTE: always set the 256 bit then remove it
	-- to always have leading zeros,
	-- and thus always 64 characters wide hashes.
	TL.toStrict $
	TL.tail $ TLB.toLazyText $ TLB.hexadecimal $
	setBit n 256

-- * Random

-- | @('randomR' i)@ returns a random integer in @[0..i-1]@.
randomR ::
 Monad m =>
 Random.RandomGen r =>
 Random.Random i =>
 Ring i =>
 i -> S.StateT r m i
randomR i = S.StateT $ return . Random.randomR (zero, i-one)

-- | @('random')@ returns a random integer
-- in the range determined by its type.
random ::
 Monad m =>
 Random.RandomGen r =>
 Random.Random i =>
 Bounded i =>
 S.StateT r m i
random = S.StateT $ return . Random.random

-- * Type 'Encryption'
-- | ElGamal-like encryption.
-- Its security relies on the /Discrete Logarithm problem/.
--
-- Because ('groupGen' '^'encNonce '^'secKey '==' 'groupGen' '^'secKey '^'encNonce),
-- knowing @secKey@, one can divide 'encryption_vault' by @('encryption_nonce' '^'secKey)@
-- to decipher @('groupGen' '^'clear)@, then the @clear@ text must be small to be decryptable,
-- because it is encrypted as a power of 'groupGen' (hence the "-like" in "ElGamal-like")
-- to enable the additive homomorphism.
--
-- NOTE: Since @('encryption_vault' '*' 'encryption_nonce' '==' 'encryption_nonce' '^' (secKey '+' clear))@,
-- then: @(logBase 'encryption_nonce' ('encryption_vault' '*' 'encryption_nonce') '==' secKey '+' clear)@.
data Encryption crypto v c = Encryption
 { encryption_nonce :: !(G crypto c)
   -- ^ Public part of the randomness 'encNonce' used to 'encrypt' the 'clear' text,
   -- equal to @('groupGen' '^'encNonce)@
 , encryption_vault :: !(G crypto c)
   -- ^ Encrypted 'clear' text,
   -- equal to @('pubKey' '^'encNone '*' 'groupGen' '^'clear)@
 } deriving (Generic)
deriving instance Eq (G crypto c) => Eq (Encryption crypto v c)
deriving instance (Show (G crypto c), Show (G crypto c)) => Show (Encryption crypto v c)
deriving instance NFData (G crypto c) => NFData (Encryption crypto v c)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => ToJSON (Encryption crypto v c) where
	toJSON Encryption{..} =
		JSON.object
		 [ "alpha" .= encryption_nonce
		 , "beta"  .= encryption_vault
		 ]
	toEncoding Encryption{..} =
		JSON.pairs
		 (  "alpha" .= encryption_nonce
		 <> "beta"  .= encryption_vault
		 )
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (Encryption crypto v c) where
	parseJSON = JSON.withObject "Encryption" $ \o -> do
		encryption_nonce <- o .: "alpha"
		encryption_vault <- o .: "beta"
		return Encryption{..}

-- | Additive homomorphism.
-- Using the fact that: @'groupGen' '^'x '*' 'groupGen' '^'y '==' 'groupGen' '^'(x'+'y)@.
instance CryptoParams crypto c => Additive (Encryption crypto v c) where
	zero = Encryption one one
	x+y = Encryption
	 (encryption_nonce x * encryption_nonce y)
	 (encryption_vault x * encryption_vault y)

-- *** Type 'EncryptionNonce'
type EncryptionNonce = E

-- | @('encrypt' pubKey clear)@ returns an ElGamal-like 'Encryption'.
--
-- WARNING: the secret encryption nonce (@encNonce@)
-- is returned alongside the 'Encryption'
-- in order to 'prove' the validity of the encrypted 'clear' text in 'proveEncryption',
-- but this secret @encNonce@ MUST be forgotten after that,
-- as it may be used to decipher the 'Encryption'
-- without the 'SecretKey' associated with 'pubKey'.
encrypt ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m => RandomGen r =>
 PublicKey crypto c -> E crypto c ->
 S.StateT r m (EncryptionNonce crypto c, Encryption crypto v c)
encrypt pubKey clear = do
	encNonce <- random
	-- NOTE: preserve the 'encNonce' for 'prove' in 'proveEncryption'.
	return $ (encNonce,)
		Encryption
		 { encryption_nonce = groupGen^encNonce
		 , encryption_vault = pubKey  ^encNonce * groupGen^clear
		 }

-- * Type 'Proof'
-- | Non-Interactive Zero-Knowledge 'Proof'
-- of knowledge of a discrete logarithm:
-- @(secret == logBase base (base^secret))@.
data Proof crypto v c = Proof
 { proof_challenge :: !(Challenge crypto c)
   -- ^ 'Challenge' sent by the verifier to the prover
   -- to ensure that the prover really has knowledge
   -- of the secret and is not replaying.
   -- Actually, 'proof_challenge' is not sent to the prover,
   -- but derived from the prover's 'Commitment's and statements
   -- with a collision resistant 'hash'.
   -- Hence the prover cannot chose the 'proof_challenge' to his/her liking.
 , proof_response :: !(E crypto c)
   -- ^ A discrete logarithm sent by the prover to the verifier,
   -- as a response to 'proof_challenge'.
   --
   -- If the verifier observes that @('proof_challenge' '==' 'hash' statement [commitment])@, where:
   --
   -- * @statement@ is a serialization of a tag, @base@ and @basePowSec@,
   -- * @commitment '==' 'commit' proof base basePowSec '=='
   --   base '^' 'proof_response' '*' basePowSec '^' 'proof_challenge'@,
   -- * and @basePowSec '==' base'^'sec@,
   --
   -- then, with overwhelming probability (due to the 'hash' function),
   -- the prover was not able to choose 'proof_challenge'
   -- yet was able to compute a 'proof_response' such that
   -- (@commitment '==' base '^' 'proof_response' '*' basePowSec '^' 'proof_challenge'@),
   -- that is to say: @('proof_response' '==' logBase base 'commitment' '-' sec '*' 'proof_challenge')@,
   -- therefore the prover knows 'sec'.
   --
   -- The prover choses 'commitment' to be a random power of @base@,
   -- to ensure that each 'prove' does not reveal any information
   -- about its secret.
 } deriving (Eq,Show,NFData,Generic)
instance Reifies v Version => ToJSON (Proof crypto v c) where
	toJSON Proof{..} =
		JSON.object
		 [ "challenge" .= proof_challenge
		 , "response"  .= proof_response
		 ]
	toEncoding Proof{..} =
		JSON.pairs
		 (  "challenge" .= proof_challenge
		 <> "response"  .= proof_response
		 )
instance
 ( CryptoParams crypto c
 , Reifies v Version
 ) => FromJSON (Proof crypto v c) where
	parseJSON = JSON.withObject "TrusteePublicKey" $ \o -> do
		proof_challenge <- o .: "challenge"
		proof_response  <- o .: "response"
		return Proof{..}

-- ** Type 'ZKP'
-- | Zero-knowledge proof.
--
-- A protocol is /zero-knowledge/ if the verifier
-- learns nothing from the protocol except that the prover
-- knows the secret.
--
-- DOC: Mihir Bellare and Phillip Rogaway. Random oracles are practical:
--      A paradigm for designing efficient protocols. In ACM-CCS’93, 1993.
newtype ZKP = ZKP BS.ByteString

-- ** Type 'Challenge'
type Challenge = E

-- ** Type 'Oracle'
-- An 'Oracle' returns the 'Challenge' of the 'Commitment's
-- by 'hash'ing them (eventually with other 'Commitment's).
--
-- Used in 'prove' it enables a Fiat-Shamir transformation
-- of an /interactive zero-knowledge/ (IZK) proof
-- into a /non-interactive zero-knowledge/ (NIZK) proof.
-- That is to say that the verifier does not have
-- to send a 'Challenge' to the prover.
-- Indeed, the prover now handles the 'Challenge'
-- which becomes a (collision resistant) 'hash'
-- of the prover's commitments (and statements to be a stronger proof).
type Oracle list crypto c = list (Commitment crypto c) -> Challenge crypto c

-- | @('prove' sec commitmentBases oracle)@
-- returns a 'Proof' that @sec@ is known
-- (by proving the knowledge of its discrete logarithm).
--
-- The 'Oracle' is given 'Commitment's equal to the 'commitmentBases'
-- raised to the power of the secret nonce of the 'Proof',
-- as those are the 'Commitment's that the verifier will obtain
-- when composing the 'proof_challenge' and 'proof_response' together
-- (with 'commit').
--
-- WARNING: for 'prove' to be a so-called /strong Fiat-Shamir transformation/ (not a weak):
-- the statement must be included in the 'hash' (along with the commitments).
--
-- NOTE: a 'random' @nonce@ is used to ensure each 'prove'
-- does not reveal any information regarding the secret @sec@,
-- because two 'Proof's using the same 'Commitment'
-- can be used to deduce @sec@ (using the special-soundness).
prove ::
 forall crypto v c list m r.
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m => RandomGen r => Functor list =>
 E crypto c ->
 list (G crypto c) ->
 Oracle list crypto c ->
 S.StateT r m (Proof crypto v c)
prove sec commitmentBases oracle = do
	nonce <- random
	let commitments = (^ nonce) <$> commitmentBases
	let proof_challenge = oracle commitments
	return Proof
	 { proof_challenge
	 , proof_response = nonce `op` (sec*proof_challenge)
	 }
	where
	-- | See comments in 'commit'.
	op =
		if reflect (Proxy @v) `hasVersionTag` versionTagQuicker
		then (-)
		else (+)

-- | Like 'prove' but quicker. It chould replace 'prove' entirely
-- when Helios-C specifications will be fixed.
proveQuicker ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m => RandomGen r => Functor list =>
 E crypto c ->
 list (G crypto c) ->
 Oracle list crypto c ->
 S.StateT r m (Proof crypto v c)
proveQuicker sec commitmentBases oracle = do
	nonce <- random
	let commitments = (^ nonce) <$> commitmentBases
	let proof_challenge = oracle commitments
	return Proof
	 { proof_challenge
	 , proof_response = nonce - sec*proof_challenge
	 }

-- | @('fakeProof')@ returns a 'Proof'
-- whose 'proof_challenge' and 'proof_response' are uniformly chosen at random,
-- instead of @('proof_challenge' '==' 'hash' statement commitments)@
-- and @('proof_response' '==' nonce '+' sec '*' 'proof_challenge')@
-- as a 'Proof' returned by 'prove'.
--
-- Used in 'proveEncryption' to fill the returned 'DisjProof'
-- with fake 'Proof's for all 'Disjunction's but the encrypted one.
fakeProof ::
 CryptoParams crypto c =>
 Monad m => RandomGen r =>
 S.StateT r m (Proof crypto v c)
fakeProof = do
	proof_challenge <- random
	proof_response  <- random
	return Proof{..}

-- ** Type 'Commitment'
-- | A commitment from the prover to the verifier.
-- It's a power of 'groupGen' chosen randomly by the prover
-- when making a 'Proof' with 'prove'.
type Commitment = G

-- | @('commit' proof base basePowSec)@ returns a 'Commitment'
-- from the given 'Proof' with the knowledge of the verifier.
commit ::
 forall crypto v c.
 Reifies v Version =>
 CryptoParams crypto c =>
 Proof crypto v c ->
 G crypto c ->
 G crypto c ->
 Commitment crypto c
commit Proof{..} base basePowSec =
	(base^proof_response) `op`
	(basePowSec^proof_challenge)
	where
	op =
		if reflect (Proxy @v) `hasVersionTag` versionTagQuicker
		then (*)
		else (/)
  -- TODO: contrary to some textbook presentations,
  -- @('*')@ should be used instead of @('/')@ to avoid the performance cost
  -- of a modular exponentiation @('^' ('groupOrder' '-' 'one'))@,
  -- this is compensated by using @('-')@ instead of @('+')@ in 'prove'.
{-# INLINE commit #-}

-- | Like 'commit' but quicker. It chould replace 'commit' entirely
-- when Helios-C specifications will be fixed.
commitQuicker ::
 CryptoParams crypto c =>
 Proof crypto v c ->
 G crypto c ->
 G crypto c ->
 Commitment crypto c
commitQuicker Proof{..} base basePowSec =
	base^proof_response *
	basePowSec^proof_challenge

-- * Type 'Disjunction'
-- | A 'Disjunction' is an 'inverse'd @('groupGen' '^'opinion)@
-- it's used in 'proveEncryption' to generate a 'Proof'
-- that an 'encryption_vault' contains a given @('groupGen' '^'opinion)@,
type Disjunction = G

booleanDisjunctions ::
 forall crypto c.
 CryptoParams crypto c =>
 [Disjunction crypto c]
booleanDisjunctions = List.take 2 $ groupGenInverses @crypto

intervalDisjunctions ::
 forall crypto c.
 CryptoParams crypto c =>
 Natural -> Natural -> [Disjunction crypto c]
intervalDisjunctions mini maxi =
	List.genericTake (fromJust $ (nat maxi + 1)`minusNaturalMaybe`nat mini) $
	List.genericDrop (nat mini) $
	groupGenInverses @crypto

-- ** Type 'DisjProof'
-- | A list of 'Proof's to prove that the opinion within an 'Encryption'
-- is indexing a 'Disjunction' within a list of them,
-- without revealing which opinion it is.
newtype DisjProof crypto v c = DisjProof [Proof crypto v c]
 deriving (Eq,Show,Generic)
 deriving newtype (NFData)
deriving newtype instance Reifies v Version => ToJSON (DisjProof crypto v c)
deriving newtype instance (Reifies v Version, CryptoParams crypto c) => FromJSON (DisjProof crypto v c)

-- | @('proveEncryption' elecPubKey voterZKP (prevDisjs,nextDisjs) (encNonce,enc))@
-- returns a 'DisjProof' that 'enc' 'encrypt's
-- the 'Disjunction' 'd' between 'prevDisjs' and 'nextDisjs'.
--
-- The prover proves that it knows an 'encNonce', such that:
-- @(enc '==' Encryption{encryption_nonce='groupGen' '^'encNonce, encryption_vault=elecPubKey'^'encNonce '*' groupGen'^'d})@
--
-- A /NIZK Disjunctive Chaum Pedersen Logarithm Equality/ is used.
--
-- DOC: Pierrick Gaudry. <https://hal.inria.fr/hal-01576379 Some ZK security proofs for Belenios>, 2017.
proveEncryption ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m => RandomGen r =>
 PublicKey crypto c -> ZKP ->
 ([Disjunction crypto c],[Disjunction crypto c]) ->
 (EncryptionNonce crypto c, Encryption crypto v c) ->
 S.StateT r m (DisjProof crypto v c)
proveEncryption elecPubKey voterZKP (prevDisjs,nextDisjs) (encNonce,enc) = do
	-- Fake proofs for all 'Disjunction's except the genuine one.
	prevFakeProofs <- replicateM (List.length prevDisjs) fakeProof
	nextFakeProofs <- replicateM (List.length nextDisjs) fakeProof
	let fakeChallengeSum =
		sum (proof_challenge <$> prevFakeProofs) +
		sum (proof_challenge <$> nextFakeProofs)
	let statement = encryptionStatement voterZKP enc
	genuineProof <- prove encNonce [groupGen, elecPubKey] $ \genuineCommitments ->
		let validCommitments = List.zipWith (encryptionCommitments elecPubKey enc) in
		let prevCommitments = validCommitments prevDisjs prevFakeProofs in
		let nextCommitments = validCommitments nextDisjs nextFakeProofs in
		let commitments = join prevCommitments <> genuineCommitments <> join nextCommitments in
		let challenge = hash statement commitments in
		let genuineChallenge = challenge - fakeChallengeSum in
		genuineChallenge
		-- NOTE: here by construction (genuineChallenge == challenge - fakeChallengeSum)
		-- thus (sum (proof_challenge <$> proofs) == challenge)
		-- as checked in 'verifyEncryption'.
	let proofs = prevFakeProofs <> (genuineProof : nextFakeProofs)
	return (DisjProof proofs)

verifyEncryption ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m =>
 PublicKey crypto c -> ZKP ->
 [Disjunction crypto c] -> (Encryption crypto v c, DisjProof crypto v c) ->
 ExceptT ErrorVerifyEncryption m Bool
verifyEncryption elecPubKey voterZKP disjs (enc, DisjProof proofs) =
	case isoZipWith (encryptionCommitments elecPubKey enc) disjs proofs of
	 Nothing ->
		throwE $ ErrorVerifyEncryption_InvalidProofLength
		 (fromIntegral $ List.length proofs)
		 (fromIntegral $ List.length disjs)
	 Just commitments ->
		return $ challengeSum ==
			hash (encryptionStatement voterZKP enc) (join commitments)
	where
	challengeSum = sum (proof_challenge <$> proofs)

-- ** Hashing
encryptionStatement ::
 CryptoParams crypto c =>
 ZKP -> Encryption crypto v c -> BS.ByteString
encryptionStatement (ZKP voterZKP) Encryption{..} =
	"prove|"<>voterZKP<>"|"
	 <> bytesNat encryption_nonce<>","
	 <> bytesNat encryption_vault<>"|"

-- | @('encryptionCommitments' elecPubKey enc disj proof)@
-- returns the 'Commitment's with only the knowledge of the verifier.
--
-- For the prover the 'Proof' comes from @fakeProof@,
-- and for the verifier the 'Proof' comes from the prover.
encryptionCommitments ::
 Reifies v Version =>
 CryptoParams crypto c =>
 PublicKey crypto c -> Encryption crypto v c ->
 Disjunction crypto c -> Proof crypto v c -> [G crypto c]
encryptionCommitments elecPubKey Encryption{..} disj proof =
	[ commit proof groupGen encryption_nonce
	  -- == groupGen ^ nonce if 'Proof' comes from 'prove'.
	  -- base==groupGen, basePowSec==groupGen^encNonce.
	, commit proof elecPubKey (encryption_vault*disj)
	  -- == elecPubKey ^ nonce if 'Proof' comes from 'prove'
	  -- and 'encryption_vault' encrypts (- logBase groupGen disj).
	  -- base==elecPubKey, basePowSec==elecPubKey^encNonce.
	]

-- ** Type 'ErrorVerifyEncryption'
-- | Error raised by 'verifyEncryption'.
data ErrorVerifyEncryption
 =   ErrorVerifyEncryption_InvalidProofLength Natural Natural
     -- ^ When the number of proofs is different than
     -- the number of 'Disjunction's.
 deriving (Eq,Show)

-- * Type 'Signature'
-- | Schnorr-like signature.
--
-- Used by each voter to sign his/her encrypted 'Ballot'
-- using his/her 'Credential',
-- in order to avoid ballot stuffing.
data Signature crypto v c = Signature
 { signature_publicKey :: !(PublicKey crypto c)
   -- ^ Verification key.
 , signature_proof     :: !(Proof crypto v c)
 } deriving (Generic)
deriving instance (NFData crypto, NFData (G crypto c)) => NFData (Signature crypto v c)
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => ToJSON (Signature crypto v c) where
	toJSON (Signature pubKey Proof{..}) =
		JSON.object
		 [ "public_key" .= pubKey
		 , "challenge"  .= proof_challenge
		 , "response"   .= proof_response
		 ]
	toEncoding (Signature pubKey Proof{..}) =
		JSON.pairs
		 (  "public_key" .= pubKey
		 <> "challenge"  .= proof_challenge
		 <> "response"   .= proof_response
		 )
instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => FromJSON (Signature crypto v c) where
	parseJSON = JSON.withObject "Signature" $ \o -> do
		signature_publicKey <- o .: "public_key"
		proof_challenge     <- o .: "challenge"
		proof_response      <- o .: "response"
		let signature_proof = Proof{..}
		return Signature{..}
