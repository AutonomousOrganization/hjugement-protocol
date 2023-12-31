module HUnit.Trustee where
import Test.Tasty
import Voting.Protocol
import qualified HUnit.Trustee.Indispensable

hunit :: Reifies v Version => Proxy v -> TestTree
hunit v =
	testGroup "Trustee"
	 [ HUnit.Trustee.Indispensable.hunit v
	 ]
