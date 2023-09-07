package tibe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/cloudflare/circl/ecc/bls12381"
)

const macSize = 32

func mac(data, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return h.Sum(nil)
}

func randomScalar() (*bls12381.Scalar, error) {
	r := &bls12381.Scalar{}
	if err := r.Random(rand.Reader); err != nil {
		return nil, err
	}

	return r, nil
}

func hashGt(gt *bls12381.Gt) ([]byte, error) {
	bts, err := gt.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hsh := sha512.Sum512_256(bts)

	return hsh[:], nil
}

func g2Hash(id []byte) *bls12381.G2 {
	tHsh := &bls12381.G2{}
	tHsh.Hash(id, []byte("g2hash"))

	return tHsh
}

func isValidSignature(msg []byte, sig *bls12381.G2, pubkey *bls12381.G1) bool {
	l := bls12381.Pair(pubkey, g2Hash(msg))
	r := bls12381.Pair(bls12381.G1Generator(), sig)

	return l.IsEqual(r)
}
