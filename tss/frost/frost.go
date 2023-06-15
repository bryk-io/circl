package frost

import (
	"fmt"
	"io"
	"sort"

	"go.bryk.io/circl/group"
	"go.bryk.io/circl/vss"
)

type PrivateKey struct {
	Suite
	key    group.Scalar
	pubKey *PublicKey
}

type PublicKey struct {
	Suite
	key group.Element
}

func GenerateKey(s Suite, rnd io.Reader) *PrivateKey {
	return &PrivateKey{s, s.g.RandomNonZeroScalar(rnd), nil}
}

func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{k.Suite, k.Suite.g.NewElement().MulGen(k.key)}
}

func (k *PrivateKey) Split(rnd io.Reader, threshold, maxSigners uint) ([]PeerSigner, vss.SecretCommitment, error) {
	ss := vss.New(rnd, threshold, k.key)
	shares := ss.Share(maxSigners)

	peers := make([]PeerSigner, len(shares))
	for i := range shares {
		peers[i] = PeerSigner{
			Suite:      k.Suite,
			threshold:  uint16(threshold),
			maxSigners: uint16(maxSigners),
			keyShare: vss.Share{
				ID:    shares[i].ID,
				Value: shares[i].Value,
			},
			myPubKey: nil,
		}
	}

	return peers, ss.CommitSecret(), nil
}

func (k *PrivateKey) SplitWithRandomIDs(rnd io.Reader, threshold, maxSigners uint) ([]PeerSigner, vss.SecretCommitment, error) {
	// create and sort a set of random IDs
	ids := make([]group.Scalar, maxSigners)
	for i := range ids {
		ids[i] = k.g.RandomScalar(rnd)
	}
	sort.SliceStable(ids, func(i, j int) bool {
		return ids[i].(fmt.Stringer).String() < ids[j].(fmt.Stringer).String()
	})

	ss := vss.New(rnd, threshold, k.key)
	peers := make([]PeerSigner, maxSigners)
	for i := range peers {
		share := ss.ShareWithID(ids[i])
		peers[i] = PeerSigner{
			Suite:      k.Suite,
			threshold:  uint16(threshold),
			maxSigners: uint16(maxSigners),
			keyShare:   share,
			myPubKey:   nil,
		}
	}
	return peers, ss.CommitSecret(), nil
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	return k.key.MarshalBinary()
}

func Verify(s Suite, pubKey *PublicKey, msg, signature []byte) bool {
	params := s.g.Params()
	Ne, Ns := params.CompressedElementLength, params.ScalarLength
	if len(signature) < int(Ne+Ns) {
		return false
	}

	REnc := signature[:Ne]
	R := s.g.NewElement()
	err := R.UnmarshalBinary(REnc)
	if err != nil {
		return false
	}

	zEnc := signature[Ne : Ne+Ns]
	z := s.g.NewScalar()
	err = z.UnmarshalBinary(zEnc)
	if err != nil {
		return false
	}

	pubKeyEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return false
	}

	chInput := append(append(append([]byte{}, REnc...), pubKeyEnc...), msg...)
	c := s.hasher.h2(chInput)

	l := s.g.NewElement().MulGen(z)
	r := s.g.NewElement().Mul(pubKey.key, c)
	r.Add(r, R)

	return l.IsEqual(r)
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.key.MarshalBinary()
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	p.key = p.Suite.g.NewElement()
	return p.key.UnmarshalBinary(data)
}
