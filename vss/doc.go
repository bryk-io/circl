/*
Package vss provides methods to split secrets into shares.

Let `n` be the number of parties, and `t` the number of corrupted
parties such that 0 <= t < n. A `(t,n)` secret sharing allows to
split a secret into `n` shares, such that the secret can be recovered
from any subset of at least `t+1` different shares.

A Shamir secret sharing [1] relies on Lagrange polynomial interpolation.
A Feldman secret sharing [2] extends Shamir's by committing the secret,
which allows to verify that a share is part of the committed secret.

`New` returns a SecretSharing compatible with Shamir secret sharing.
The SecretSharing can be verifiable (compatible with Feldman secret
sharing) using the `CommitSecret` and `Verify` functions.

In this implementation, secret sharing is defined over the scalar field
of a prime order group.

References

	[1] https://dl.acm.org/doi/10.1145/359168.359176/
	[2] https://ieeexplore.ieee.org/document/4568297/
*/
package vss
