package vss

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/group"
)

func ExampleSecretSharing() {
	g := group.P256
	t := uint(2)
	n := uint(5)

	secret := g.RandomScalar(rand.Reader)
	ss := New(rand.Reader, t, secret)
	shares := ss.Share(n)

	got, err := Recover(t, shares[:t])
	fmt.Printf("Recover secret: %v\nError: %v\n", secret.IsEqual(got), err)

	got, err = Recover(t, shares[:t+1])
	fmt.Printf("Recover secret: %v\nError: %v\n", secret.IsEqual(got), err)
	// Output:
	// Recover secret: false
	// Error: vss: number of shares (n=2) must be above the threshold (t=2)
	// Recover secret: true
	// Error: <nil>
}

func ExampleVerify() {
	g := group.P256
	t := uint(2)
	n := uint(5)

	secret := g.RandomScalar(rand.Reader)
	ss := New(rand.Reader, t, secret)
	shares := ss.Share(n)
	verifiers := ss.CommitSecret()

	for i := range shares {
		ok := Verify(t, shares[i], verifiers)
		fmt.Printf("Share %v is valid: %v\n", i, ok)
	}

	got, err := Recover(t, shares)
	fmt.Printf("Recover secret: %v\nError: %v\n", secret.IsEqual(got), err)
	// Output:
	// Share 0 is valid: true
	// Share 1 is valid: true
	// Share 2 is valid: true
	// Share 3 is valid: true
	// Share 4 is valid: true
	// Recover secret: true
	// Error: <nil>
}
