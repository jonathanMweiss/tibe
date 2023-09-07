package tibe

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"github.com/cloudflare/circl/ecc/bls12381"
	"runtime"
)

// Encrypter is the interface for encrypting messages (the master public key of an IBE scheme).
type Encrypter interface {
	Encrypt(ID, msg []byte) (Cipher, error)
}

// Decrypter is the interface for decrypting messages (the private key of an IBE scheme, tied to a specific ID).
type Decrypter interface {
	Decrypt(c Cipher) ([]byte, error)
}

// master represents the master key and secret key of the IBE scheme.
type master interface {
	Decrypter(id []byte) Decrypter
	// GetMasterPublicKey returns the master public key of the IBE scheme. The MPK should be used to encrypt messages
	// using a specific ID.
	GetMasterPublicKey() (MasterPublicKey, error)
}

// VssIbeNode is a node in the VSS IBE scheme. Can receive shares from other Ibe nodes, and reconstruct
// Decrypter for specific shares.
// NOTE: This is a POC, as a result, we don't run a full VSS, and assume the shares are valid.
// VSS can be done using the exPoly of each Share. Only need to verify all servers received the same exPoly.
type VssIbeNode interface {
	master

	VssShares(n int) ([]VssShare, error)

	// EncryptFor takes a wanted node name, will encrypt the message under that node's public key, and tie the
	// specific encryption to a given ID. that is, any node that wants to decrypt, will need to get a secret key
	// tied to that nodename, and that specific ID.
	// Essentially, similar to using an Encrypter tied specifically to otherNodeName + ID.
	EncryptFor(otherNodeName string, ID, msg []byte) (Cipher, error)

	// Vote generates the part of a secret key using the VssShare this Node received.
	// collecting enough votes will allow to reconstruct the secret key: H(id)^{sum(votes)} = H(ID)^P(0) where P is
	// the polynoimial of otherNodeName.
	Vote(otherNodeName string, id []byte) (Vote, error)
	ValidateVote(otherNodeName string, v Vote) error

	// ReceiveShare Assumes you verified the share using the public ExponentPoly of the otherNodeName. (example in test)
	ReceiveShare(otherNodeName string, shr VssShare)
	ReconstructDecrypter(otherNodeName string, votes []Vote) (Decrypter, error)
}

// Cipher is the ciphertext, can be decrypted by a specific Decrypter.
type Cipher struct {
	Gr        *bls12381.G1
	Mac       []byte
	Encrypted []byte
}

func (c *Cipher) Copy() Cipher {
	gr := &bls12381.G1{}
	identitiy := &bls12381.G1{}
	identitiy.SetIdentity()
	gr.Add(c.Gr, identitiy)
	return Cipher{
		Gr:        gr,
		Mac:       append([]byte{}, c.Mac...),
		Encrypted: append([]byte{}, c.Encrypted...),
	}
}

func (c *Cipher) ToBuffer(buffer *bytes.Buffer) {
	buffer.Write(c.Gr.Bytes())
	buffer.Write(c.Mac)
	buffer.Write(c.Encrypted)
}

func (c *Cipher) Size() int {
	return bls12381.G1Size + len(c.Mac) + len(c.Encrypted)
}

func (c *Cipher) SetBytes(bts []byte) error {
	if c.Gr == nil {
		c.Gr = &bls12381.G1{}
	}

	if err := c.Gr.SetBytes(bts[:bls12381.G1Size]); err != nil {
		return err
	}

	c.Mac = bts[bls12381.G1Size : bls12381.G1Size+macSize]
	c.Encrypted = bts[bls12381.G1Size+macSize:]

	return nil
}

// MasterPublicKey is an Encrypter.
type MasterPublicKey struct {
	G1 *bls12381.G1
}

func NewMasterPublicKey() MasterPublicKey {
	return MasterPublicKey{G1: &bls12381.G1{}}
}

// a decryptor tied to a specific ID.
type idBasedPrivateKey struct {
	*bls12381.G2
}

// Encrypt generate a Cipher.
func (p MasterPublicKey) Encrypt(ID, msg []byte) (Cipher, error) {
	r, err := randomScalar()
	if err != nil {
		return Cipher{}, err
	}

	h := g2Hash(ID)
	tmp := &bls12381.G1{}
	tmp.ScalarMult(r, p.G1)

	k, err := hashGt(bls12381.Pair(tmp, h))
	if err != nil {
		return Cipher{}, err
	}

	c, err := aesEncrypt(k, msg)
	if err != nil {
		return Cipher{}, err
	}

	tmp.ScalarMult(r, bls12381.G1Generator())

	return Cipher{
		Gr: tmp,
		// TODO: verify with GIL this is secure authentication over the ciphertext.
		Mac:       mac(append(tmp.Bytes(), c...), k),
		Encrypted: c,
	}, nil
}

func (p *MasterPublicKey) Bytes() []byte {
	return p.G1.Bytes()
}

func (p *MasterPublicKey) SetBytes(bytes []byte) error {
	if p.G1 == nil {
		p.G1 = &bls12381.G1{}
	}

	return p.G1.SetBytes(bytes)

}

// Decrypt decrypts a Cipher.
func (sk idBasedPrivateKey) Decrypt(c Cipher) ([]byte, error) {
	k, err := hashGt(bls12381.Pair(c.Gr, sk.G2))
	if err != nil {
		return nil, err
	}

	if !hmac.Equal(c.Mac, mac(append(c.Gr.Bytes(), c.Encrypted...), k)) {
		return nil, fmt.Errorf("mac mismatch")
	}

	return aesDecrypt(k, c.Encrypted)
}

// Node is one that can participate in the TIBE scheme. it should be able to:
// 1. Gen IBE private keys (with its master key).
// 2. Receive shares from other nodes.
// 3. Reconstruct a specific IBE key from a set of votes.
// 4. compute Decrypter tied to specific Ids.
type Node struct {
	*shareableIbeScheme
	Shares    *typedMap[string, VssShare]
	workQueue chan validateTask
}

func (t Node) EncryptFor(otherNodeName string, ID, msg []byte) (Cipher, error) {
	shr, ok := t.Shares.Load(otherNodeName)
	if !ok {
		return Cipher{}, fmt.Errorf("no share for node %v", otherNodeName)
	}

	return shr.MasterPublicKey.Encrypt(ID, msg)
}

// VssShare holds the share of the underlying polynomial, and the public polynomial (exPoly)
type VssShare struct {
	*ExponentPoly
	PolyShare
	MasterPublicKey
}

type validateTask struct {
	*Vote
	*ExponentPoly
	response chan error
}

// NewNode is the constructor for a VssIbeNode.
// Poly must be kept Secret. Use poly to generate its ExponentPoly and share it publicly with other nodes (so they can
// verify the shares this Node generates).
func NewNode(poly Poly) VssIbeNode {
	ibe := newShareableIbeScheme(poly)

	nd := Node{
		shareableIbeScheme: &ibe,
		Shares:             &typedMap[string, VssShare]{},
		workQueue:          make(chan validateTask, runtime.NumCPU()),
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for tsk := range nd.workQueue {
				vote := tsk.Vote
				publicShare := tsk.ExponentPoly.GetPublicShare(uint64(vote.Index))

				if !isValidSignature(vote.ID, vote.Sig, publicShare) {
					tsk.response <- fmt.Errorf("invalid signature: %v", vote)
				}

				close(tsk.response) // sending nil if not full
			}
		}()
	}

	return nd
}

// Vote is the proper to share a part of an Decrypter.
func (t Node) Vote(otherNodeName string, id []byte) (Vote, error) {
	shr, ok := t.Shares.Load(otherNodeName)
	if !ok {
		return Vote{}, fmt.Errorf("no share for node %v", otherNodeName)
	}

	sk := shr.PolyShare.Value

	sig := g2Hash(id)
	sig.ScalarMult(sk, sig)

	return Vote{
		ID:    id,
		Index: shr.PolyShare.Index,
		Sig:   sig,
	}, nil
}

// ReceiveShare assumes trusted content.
func (t Node) ReceiveShare(otherNodeName string, shr VssShare) {
	// TODO verify share:
	t.Shares.Store(otherNodeName, shr)
}

func (t Node) ValidateVote(otherNodeName string, v Vote) error {
	shr, ok := t.Shares.Load(otherNodeName)
	if !ok {
		return fmt.Errorf("no share for node %v", otherNodeName)
	}
	// should verify each vote. (this is why one would need the exPoly.

	expoly := shr.ExponentPoly
	rsp := make(chan error, 1)
	t.workQueue <- validateTask{
		Vote:         &v,
		ExponentPoly: expoly,
		response:     rsp,
	}

	return <-rsp
}

// ReconstructDecrypter receives a specific node name and a set of votes to reconstruct the Decrypter.
func (t Node) ReconstructDecrypter(nodeName string, votes []Vote) (Decrypter, error) {
	if len(votes) <= 0 {
		return idBasedPrivateKey{}, fmt.Errorf("no votes")
	}

	shr, ok := t.Shares.Load(nodeName)
	if !ok {
		return idBasedPrivateKey{}, fmt.Errorf("no share for node/index %v", votes[0].Index)
	}
	// should verify each vote. (this is why one would need the exPoly.

	expoly := shr.ExponentPoly
	resps := make([]chan error, len(votes))

	for i, vote := range votes {
		vt := vote
		rsp := make(chan error, 1)
		t.workQueue <- validateTask{
			Vote:         &vt,
			ExponentPoly: expoly,
			response:     rsp,
		}

		resps[i] = rsp
	}

	for i := 0; i < len(votes); i++ {
		if err := <-resps[i]; err != nil {
			return idBasedPrivateKey{}, err
		}
	}

	skey, err := reconstructSecretIbeKey(votes, expoly.Threshold())
	if err != nil {
		return idBasedPrivateKey{}, err
	}

	return idBasedPrivateKey{skey}, nil
}

type shareableIbeScheme struct {
	P  *Poly
	PK MasterPublicKey
	S  *bls12381.Scalar
}

func (I shareableIbeScheme) VssShares(n int) ([]VssShare, error) {
	expoly := I.P.GetExponentPoly()
	polyShares := I.P.CreateShares(n)
	shrs := make([]VssShare, n)

	for i := range shrs {
		mpk, err := I.GetMasterPublicKey()
		if err != nil {
			return nil, err
		}

		shrs[i] = VssShare{
			ExponentPoly:    expoly,
			PolyShare:       polyShares[i],
			MasterPublicKey: mpk,
		}

	}
	return shrs, nil
}

func newShareableIbeScheme(poly Poly) shareableIbeScheme {
	cpyPoly := poly.Copy()
	masterSecret := cpyPoly.Secret()
	masterpub := &bls12381.G1{}
	masterpub.ScalarMult(masterSecret, bls12381.G1Generator())

	return shareableIbeScheme{
		P:  cpyPoly,
		PK: MasterPublicKey{masterpub},
		S:  masterSecret,
	}
}

func (I shareableIbeScheme) Decrypter(id []byte) Decrypter {
	sk := g2Hash(id)
	sk.ScalarMult(I.S, sk)

	return idBasedPrivateKey{sk}
}

func (I shareableIbeScheme) GetMasterPublicKey() (MasterPublicKey, error) {
	mpkCopy := &bls12381.G1{}
	if err := mpkCopy.SetBytes(I.PK.G1.Bytes()); err != nil {
		return MasterPublicKey{}, err
	}

	return MasterPublicKey{G1: mpkCopy}, nil
}
