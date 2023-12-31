module QuickCheck where
import Test.Tasty
import Voting.Protocol
import qualified QuickCheck.Election
import qualified QuickCheck.Trustee

quickchecks :: Reifies v Version => Proxy v -> TestTree
quickchecks v =
	testGroup "QuickCheck"
	 [ QuickCheck.Election.quickcheck v
	 , QuickCheck.Trustee.quickcheck v
	 ]
