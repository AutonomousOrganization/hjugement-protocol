# Voting protocol

## Ballot
Ballots are encrypted using public-key cryptography
secured by the <i>Discrete Logarithm problem</i>:
finding `x` in <code>(g^x `mod` p)</code>, where `p` is a large prime
and `g` a generator of `Gq`, the multiplicative subgroup of order `q`,
in `Fp` (the finite prime field whose characteristic is `p`).

Here, `p` is 2048-bit and `q` is 256-bit.

The signing (Schnorr-like), the encrypting (ElGamal-like)
and the <i>Decisional Diffe Hellman</i> (DDH) assumption,
all rely on the hardness of that problem.

### Ballot signing
The <i>Schnorr protocol</i> is used to prove that a voter has knowledge
of the secret key used to sign their votes.

### Voter's credential
A voter's credential is a secret key (the signing key)
from which a public part can be derived (the verification key).

The association between the public part and the corresponding voter's identity
does not need to be known, and actually should not be disclosed to satisfy
e.g. the French requirements regarding voting systems.
Using credentials prevent the submission of duplicated ballots
(because they are added as an additional input to the random oracle
in the <i>non-interactive zero-knowledge</i> (NIZK) proofs for ciphertext well-formedness).
This allows a testing of duplicates which depends only on the size of the number of voters,
and thus enables Helios-C to scale for larger elections while attaining correctness.

## Tallying
Ballots are added without being decrypted
because adding (multiplying actually) ciphertexts then decrypting,
is like decrypting then adding plaintexts (<i>additive homomorphism</i>).
Which requires to solve the <i>Discrete Logarithm Problem</i>
for numbers in the order of the number of voters,
which is not hard for small numbers (with a lookup table as here,
or with Pollard’s rho algorithm for logarithms).

## Verifying
The <i>Chaum-Pedersen protocol</i> (proving an equality of discrete logarithms)
is used to prove that ciphertexts are well-formed
(encrypting a 0 or a 1… or any expected natural) without decrypting them.
Which is known as a <i>Disjunctive Chaum-Pedersen</i> proof of partial knowledge.  
See: [Some ZK security proofs for Belenios](https://hal.inria.fr/hal-01576379).

A <i>strong Fiat-Shamir transformation</i> is used
to transform the <i>interactive zero-knowledge</i> (IZK) <i>Chaum-Pedersen protocol</i>
into a <i>non-interactive zero-knowledge</i> (NIZK) proof, using a SHA256 hash.  
See: [How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios](https://eprint.iacr.org/2016/771.pdf).

## Public Key Infrastructure
(TODO) A Pedersen's <i>distributed key generation</i> (DKG) protocol
coupled with ElGamal keys (under the DDH assumption),
is used to have a fully distributed semantically secure encryption.
