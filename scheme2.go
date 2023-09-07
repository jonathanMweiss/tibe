package tibe

import (
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/ecc/bls12381"
)

// Publisher can Hide some message under a given ID, to reveal this secret, enough Publishers must Vote over an ID.
// once enough valid votes (use Verify to validate) are collected, any secret that is tied to that ID can be revealed by using Reveal.
type Publisher interface {
	// Hide creates a secret that can be opened when enough IbePublishers Vote for the Secret's ID.
	Hide(ID, msg []byte) (Secret, error)

	Vote(ID []byte) Vote
	Verify(v Vote) bool
	Reveal(votes []Vote, secret Secret) ([]byte, error)
}

// Vote specifies a signature, and the index of the signer along with what the id that is signed.
type Vote struct {
	Index int
	ID    []byte
	Sig   Signature
}

// Player is used to create a shared secret with a group of other players such that
// they can all decrypt a message encrypted with the shared secret.
type Player struct {
	t         int
	Index     int
	Secretkey *bls12381.Scalar
	PublicKey *bls12381.G1

	// used to verify the signatures from other players
	PublicKeys      []PublicKey
	SharedPublickey *bls12381.G1
}

// Signature is a signature on a message.
type Signature *bls12381.G2

// PublicKey is a public key of a Publisher: g^P(i).
type PublicKey struct {
	Index int // index of the share
	*bls12381.G1
}

func (p PublicKey) Marshal() []byte {
	bts := p.G1.Bytes()

	bf := make([]byte, len(bts)+4)
	binary.BigEndian.PutUint32(bf, uint32(p.Index))
	copy(bf[4:], bts)

	return bf
}

func (p *PublicKey) SetBytes(bts []byte) error {
	if p == nil {
		return ErrNilReceiver
	}

	if p == nil {
		return fmt.Errorf("nil public key")
	}

	if len(bts) < 4 {
		return fmt.Errorf("invalid public key")
	}

	p.Index = int(binary.BigEndian.Uint32(bts))

	p.G1 = &bls12381.G1{}
	return p.G1.SetBytes(bts[4:])
}

// NewPublisher is the constructor of a Publisher.
// the privateShare is a secret share P(i) from some unknown Poly. (on distributed setting with no trusted dealer - assumes DKG distributed the shares)
// the public keys are public parts of a poly: g^{P(i)}.
func NewPublisher(threshold int, privateKey PolyShare, pubkeys []PublicKey) (*Player, error) {
	xys := map[int]*bls12381.G1{}
	indices := make([]int, threshold)

	for i, pkey := range pubkeys {
		if i == threshold {
			break
		}

		xys[pkey.Index] = pkey.G1
		indices[i] = pkey.Index
	}

	sharedpkey, err := computeSharedPubkey(threshold, xys, indices)
	if err != nil {
		return nil, err
	}

	return &Player{
		t:               threshold,
		Index:           privateKey.Index,
		Secretkey:       privateKey.Value,
		PublicKey:       pubkeys[privateKey.Index-1].G1,
		PublicKeys:      pubkeys,
		SharedPublickey: sharedpkey,
	}, nil
}

// Vote is the proper way to create a vote in favour of releasing any secret with the given id.
// with enough unique votes a Publisher can reveal a message.
func (p *Player) Vote(id []byte) Vote {
	return Vote{
		Index: p.Index,
		ID:    id,
		Sig:   p.sign(id),
	}
}

// Verify ensures the vote is valid.
func (p *Player) Verify(v Vote) bool {
	return isValidSignature(v.ID, v.Sig, p.PublicKeys[v.Index-1].G1)
}

// Secret represent any message that was hidden using a Hiding key.
type Secret struct {
	ReconstructProperties
	Encrypted []byte
}

// Hide takes a message, calculate a Hiding key using the ID and encrypt the message with it.
func (p *Player) Hide(ID, msg []byte) (Secret, error) {
	encKey, err := createEncryptionKey(ID, p.SharedPublickey)
	if err != nil {
		return Secret{}, err
	}

	cipher, err := encKey.encrypt(msg)
	if err != nil {
		return Secret{}, err
	}

	return Secret{
		ReconstructProperties: encKey.ReconstructProperties,
		Encrypted:             cipher,
	}, nil
}

// Reveal is the proper way to reconstruct a secret into a message.
// Note: Assume votes slice are verified!
func (p *Player) Reveal(votes []Vote, secret Secret) ([]byte, error) {
	// TODO: make certain that if we have already found the key for a specific ID we don't reconstruct it again.
	sk, err := reconstructSecretIbeKey(votes, p.t)
	if err != nil {
		return nil, err
	}

	return decrypt(sk, secret.ReconstructProperties, secret.Encrypted)
}

func computeSharedPubkey(threshold int, xys map[int]*bls12381.G1, indices []int) (*bls12381.G1, error) {
	shrdpk := &bls12381.G1{}
	shrdpk.SetIdentity()

	for i, pkI := range xys {
		multiplier, err := newLagrangeIndexMultiplier(threshold-1, i, indices)
		if err != nil {
			return nil, err
		}

		g := &bls12381.G1{}
		g.ScalarMult(multiplier.Value, pkI)
		shrdpk.Add(shrdpk, g)
	}

	return shrdpk, nil
}

func createEncryptionKey(id []byte, publicKey *bls12381.G1) (hidingKey, error) {
	r, err := randomScalar()
	if err != nil {
		return hidingKey{}, err
	}

	pkR := &bls12381.G1{}
	pkR.ScalarMult(r, publicKey)

	hsh, err := hashGt(bls12381.Pair(pkR, g2Hash(id)))
	if err != nil {
		return hidingKey{}, err
	}

	gr := &bls12381.G1{}
	gr.ScalarMult(r, bls12381.G1Generator())

	return hidingKey{
		ReconstructProperties: ReconstructProperties{
			ID:          id,
			HidingValue: gr,
		},
		Key: hsh,
	}, nil
}

// ReconstructProperties are essentially the values released with any Secret, and are used to reconstruct the secret
// once possible.
type ReconstructProperties struct {
	// ID + HidingValue are enough to reconstruct the key ( as long as there are enough willing players)
	ID          []byte
	HidingValue *bls12381.G1 // g^r
}

type hidingKey struct {
	ReconstructProperties
	Key []byte
}

func (h *hidingKey) encrypt(m []byte) ([]byte, error) {
	// should put the identifying values in m.
	return aesEncrypt(h.Key, m)
}

func decrypt(IbeSecretKEy *bls12381.G2, p ReconstructProperties, ciphertext []byte) ([]byte, error) {
	k, err := hashGt(bls12381.Pair(p.HidingValue, IbeSecretKEy))
	if err != nil {
		return nil, err
	}

	return aesDecrypt(k, ciphertext)
}

func reconstructSecretIbeKey(votes []Vote, threshold int) (*bls12381.G2, error) {
	if len(votes) < threshold {
		return nil, fmt.Errorf("not enough votes to reconstruct secret key")
	}

	votes = votes[:threshold]
	indices := make([]int, len(votes))

	for i, v := range votes {
		indices[i] = v.Index
	}

	sum := &bls12381.G2{}
	sum.SetIdentity()

	for _, vote := range votes {
		li, err := newLagrangeIndexMultiplier(threshold-1, vote.Index, indices)
		if err != nil {
			return nil, err
		}

		tmp := &bls12381.G2{}
		tmp.ScalarMult(li.Value, vote.Sig)
		sum.Add(sum, tmp)
	}

	// sum should be equal to H(t)^{P(0)}
	return sum, nil
}

func (p *Player) sign(id []byte) *bls12381.G2 {
	g := g2Hash(id)
	g.ScalarMult(p.Secretkey, g)

	return g
}
