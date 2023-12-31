{-# LANGUAGE OverloadedStrings #-}
module HUnit.Credential where

import Test.Tasty.HUnit
import qualified Control.Monad.Trans.State.Strict as S
import qualified System.Random as Random

import Voting.Protocol
import Utils

hunit :: Reifies v Version => Proxy v -> TestTree
hunit _v = testGroup "Credential"
 [ testGroup "randomCredential"
	 [ testCase "0" $
		S.evalState randomCredential (Random.mkStdGen 0) @?=
			Credential "xLcs7ev6Jy6FHHE"
	 ]
 , testGroup "randomUUID"
	 [ testCase "0" $
		S.evalState randomUUID (Random.mkStdGen 0) @?=
			UUID "xLcs7ev6Jy6FHH"
	 ]
 , testGroup "readCredential" $
		let (==>) inp exp =
			testCase (show inp) $ readCredential inp @?= exp in
	 [ "" ==> Left ErrorToken_Length
	 , "xLcs7ev6Jy6FH_E"  ==> Left (ErrorToken_BadChar '_')
	 , "xLcs7ev6Jy6FHIE"  ==> Left (ErrorToken_BadChar 'I')
	 , "xLcs7ev6Jy6FH0E"  ==> Left (ErrorToken_BadChar '0')
	 , "xLcs7ev6Jy6FHOE"  ==> Left (ErrorToken_BadChar 'O')
	 , "xLcs7ev6Jy6FHlE"  ==> Left (ErrorToken_BadChar 'l')
	 , "xLcs7ev6Jy6FH6"   ==> Left ErrorToken_Length
	 , "xLcs7ev6Jy6FHHy1" ==> Left ErrorToken_Length
	 , "xLcs7ev6Jy6FHHF"  ==> Left ErrorToken_Checksum
	 , "xLcs7ev6Jy6FHHE"  ==> Right (Credential "xLcs7ev6Jy6FHHE")
	 ]
 , testGroup "credentialSecretKey" $
	 [  testSecretKey beleniosFFC
		 (UUID "xLcs7ev6Jy6FHH")
		 (Credential "xLcs7ev6Jy6FHHE")
		 24202898752499029126606335829564687069186982035759723128887013101942425902424
	 ]
 ]

testSecretKey ::
 ReifyCrypto crypto => Key crypto =>
 crypto -> UUID -> Credential -> Natural -> TestTree
testSecretKey crypto uuid cred exp =
	reifyCrypto crypto $ \(_c::Proxy c) ->
		testCase (show (uuid,cred)) $
			credentialSecretKey @_ @c uuid cred @?= E exp
