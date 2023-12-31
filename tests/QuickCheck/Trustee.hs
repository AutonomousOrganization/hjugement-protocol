{-# OPTIONS -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-} -- for Reifies instances
module QuickCheck.Trustee where

import Test.Tasty.QuickCheck
import qualified Data.Text as Text

import Voting.Protocol

import Utils
import QuickCheck.Election ()

quickcheck :: Reifies v Version => Proxy v -> TestTree
quickcheck v =
	testGroup "Trustee" $
	 [ testGroup "verifyIndispensableTrusteePublicKey" $
		 [ reify weakFFC $ testIndispensableTrusteePublicKey v
		 , reify beleniosFFC $ testIndispensableTrusteePublicKey v
		 ]
	 ]

testIndispensableTrusteePublicKey ::
 Reifies v Version =>
 CryptoParams crypto c =>
 Key crypto =>
 Proxy v -> Proxy c -> TestTree
testIndispensableTrusteePublicKey (_v::Proxy v) (c::Proxy c) =
	testGroup (Text.unpack $ cryptoName (reflect c))
	 [ testProperty "Right" $ \seed ->
		isRight $ runExcept $
			(`evalStateT` mkStdGen seed) $ do
				trusteeSecKey :: SecretKey crypto c <- randomSecretKey
				trusteePubKey :: TrusteePublicKey crypto v c
				 <- proveIndispensableTrusteePublicKey trusteeSecKey
				lift $ verifyIndispensableTrusteePublicKey trusteePubKey
	 ]

instance
 ( Reifies v Version
 , CryptoParams crypto c
 ) => Arbitrary (TrusteePublicKey crypto v c) where
	arbitrary = do
		trustee_PublicKey <- arbitrary
		trustee_SecretKeyProof <- arbitrary
		return TrusteePublicKey{..}
