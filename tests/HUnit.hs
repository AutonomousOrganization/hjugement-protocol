module HUnit where
import Test.Tasty
import Voting.Protocol
import qualified HUnit.FFC
import qualified HUnit.Credential
import qualified HUnit.Election
import qualified HUnit.Trustee

hunits :: Reifies v Version => Proxy v -> TestTree
hunits v =
	testGroup "HUnit"
	 [ HUnit.FFC.hunit v
	 , HUnit.Credential.hunit v
	 , HUnit.Election.hunit v
	 , HUnit.Trustee.hunit v
	 ]
