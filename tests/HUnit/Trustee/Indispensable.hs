{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
module HUnit.Trustee.Indispensable where

import Test.Tasty.HUnit
import qualified Data.Text as Text
import qualified System.Random as Random
import qualified Text.Printf as Printf

import Voting.Protocol

import Utils

hunit :: Reifies v Version => Proxy v -> TestTree
hunit v = testGroup "Indispensable" $
 [ testGroup "verifyIndispensableTrusteePublicKey" $
	 [ testsVerifyIndispensableTrusteePublicKey v weakFFC
	 ]
 , testGroup "verifyTally" $
	 [ testsVerifyTally v weakFFC
	 , testsVerifyTally v beleniosFFC
	 ]
 ]

testsVerifyIndispensableTrusteePublicKey ::
 Reifies v Version =>
 ReifyCrypto crypto => Key crypto =>
 Proxy v -> crypto -> TestTree
testsVerifyIndispensableTrusteePublicKey v crypto =
	testGroup (Text.unpack $ cryptoName crypto)
	 [ testVerifyIndispensableTrusteePublicKey v crypto 0 (Right ())
	 ]

testVerifyIndispensableTrusteePublicKey ::
 forall crypto v.
 ReifyCrypto crypto => Key crypto =>
 Reifies v Version => Proxy v ->
 crypto -> Int -> Either ErrorTrusteePublicKey () -> TestTree
testVerifyIndispensableTrusteePublicKey (_v::Proxy v) crypto seed exp =
	reifyCrypto crypto $ \(_c::Proxy c) ->
		let got =
			runExcept $
			(`evalStateT` Random.mkStdGen seed) $ do
				trusteeSecKey :: SecretKey crypto c <- randomSecretKey
				trusteePubKey :: TrusteePublicKey crypto v c <- proveIndispensableTrusteePublicKey trusteeSecKey
				lift $ verifyIndispensableTrusteePublicKey trusteePubKey
		in
		testCase (Text.unpack $ cryptoName @crypto crypto) $
			got @?= exp

testsVerifyTally ::
 ReifyCrypto crypto => Key crypto =>
 Reifies v Version => Proxy v ->
 crypto -> TestTree
testsVerifyTally v crypto =
	testGroup (Text.unpack $ cryptoName crypto)
	 [ testVerifyTally v crypto 0 1 1 1
	 , testVerifyTally v crypto 0 2 1 1
	 , testVerifyTally v crypto 0 1 2 1
	 , testVerifyTally v crypto 0 2 2 1
	 , testVerifyTally v crypto 0 5 10 5
	 ]

testVerifyTally ::
 Reifies v Version =>
 ReifyCrypto crypto => Key crypto =>
 Proxy v -> crypto -> Int -> Natural -> Natural -> Natural -> TestTree
testVerifyTally (_v::Proxy v) crypto seed nTrustees nQuests nChoices =
	let clearTallyResult = dummyTallyResult nQuests nChoices in
	let decryptedTallyResult :: Either ErrorTally [[Natural]] =
		reifyCrypto crypto $ \(_c::Proxy c) ->
			runExcept $
			(`evalStateT` Random.mkStdGen seed) $ do
				secKeyByTrustee :: [SecretKey crypto c] <-
					replicateM (fromIntegral nTrustees) $ randomSecretKey
				trusteePubKeys
				 :: [TrusteePublicKey crypto v c]
				 <- forM secKeyByTrustee $ proveIndispensableTrusteePublicKey
				let pubKeyByTrustee = trustee_PublicKey <$> trusteePubKeys
				let elecPubKey = combineIndispensableTrusteePublicKeys trusteePubKeys
				(encTally, countMax) <- encryptTallyResult elecPubKey clearTallyResult
				decShareByTrustee
				 :: [DecryptionShare crypto v c]
				 <- forM secKeyByTrustee $ proveDecryptionShare encTally
				lift $ verifyDecryptionShareByTrustee encTally pubKeyByTrustee decShareByTrustee
				tally@Tally{..} <- lift $
					proveTally (encTally, countMax) decShareByTrustee $
						combineIndispensableDecryptionShares pubKeyByTrustee
				lift $ verifyTally tally $
					combineIndispensableDecryptionShares pubKeyByTrustee
				return tally_countByChoiceByQuest
	in
	testCase (Printf.printf "#T=%i,#Q=%i,#C=%i (%i maxCount)"
	 nTrustees nQuests nChoices
	 (dummyTallyCount nQuests nChoices)) $
		decryptedTallyResult @?= Right clearTallyResult

dummyTallyCount :: Natural -> Natural -> Natural
dummyTallyCount quest choice = quest * choice

dummyTallyResult :: Natural -> Natural -> [[Natural]]
dummyTallyResult nQuests nChoices =
	[ [ dummyTallyCount q c | c <- [1..nChoices] ]
	| q <- [1..nQuests]
	]

encryptTallyResult ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Monad m => RandomGen r =>
 PublicKey crypto c -> [[Natural]] -> StateT r m (EncryptedTally crypto v c, Natural)
encryptTallyResult pubKey countByChoiceByQuest =
	(`runStateT` 0) $
		forM countByChoiceByQuest $
			mapM $ \count -> do
				modify' $ max count
				(_encNonce, enc) <- lift $ encrypt pubKey (fromNatural count)
				return enc

