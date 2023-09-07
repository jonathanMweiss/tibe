package tibe

import (
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/ecc/bls12381"
	"strconv"
	"sync"
)

// ExponentPoly is a public broadcast of a polynomial value. [g^{S}, g^{a_1}, g^{a_2}, ..., g^{a_n}]
// it can be used to verify VSS shares, and to calculate the public share (key) of a player in a VSS protocol.
type ExponentPoly struct {
	Coefs []*bls12381.G1
	// GetPublicShare is an expensive computation, to avoid that we cache the results.
	cache sync.Map
}

// Threshold returns the threshold of the underlying polynomial.
func (e *ExponentPoly) Threshold() int {
	return len(e.Coefs) + 1
}

// GetPublicShare is responsible for calculating the value g^P(i) for the underlying Polynomial.
// g^P(i) = g^a_0 + g^a_1 * i + g^a_2 * i^2 + ... + g^a_n * i^n which can be used as the public key for the secret P(i).
func (e *ExponentPoly) GetPublicShare(i uint64) *bls12381.G1 {
	if i == 0 {
		return e.Coefs[0]
	}

	if v, ok := e.cache.Load(i); ok {
		return v.(*bls12381.G1)
	}

	f := func() {
		v := &bls12381.Scalar{}
		v.SetUint64(i)

		vCopy := &bls12381.Scalar{}
		vCopy.SetUint64(i)

		res := &bls12381.G1{}
		res.SetIdentity()

		// eval the poly at i:
		for i := 1; i < len(e.Coefs); i++ {
			coef := &bls12381.G1{}
			coef.ScalarMult(v, e.Coefs[i])
			res.Add(res, coef)
			// advance to the next exponent...
			v.Mul(v, vCopy)
		}
		res.Add(e.Coefs[0], res)
		e.cache.Store(i, res)
	}

	doOnceKey := strconv.FormatUint(i, 10)
	// ensuring this computation will be used only once.
	o, _ := e.cache.LoadOrStore(doOnceKey, &sync.Once{})

	once, ok := o.(*sync.Once)
	if !ok {
		panic("failed to cast to sync.Once")
	}

	once.Do(f)

	v, ok := e.cache.Load(i)
	if !ok {
		panic("ExponentPoly.GetPublicShare: couldn't create public share")
	}

	return v.(*bls12381.G1)
}

// VerifyShare verifies that a share is valid for the given exponent polynomial.. that is:
// g^P(i) = g^a_0 + g^a_1 * i + g^a_2 * i^2
func (e *ExponentPoly) VerifyShare(index uint64, share *bls12381.Scalar) bool {
	actual := &bls12381.G1{}
	actual.ScalarMult(share, bls12381.G1Generator())

	return actual.IsEqual(e.GetPublicShare(index))
}

func (e *ExponentPoly) Marshal() []byte {
	bts := make([]byte, 4+len(e.Coefs)*bls12381.G1Size)
	binary.BigEndian.PutUint32(bts, uint32(len(e.Coefs)))

	for i, c := range e.Coefs {
		copy(bts[4+i*bls12381.G1Size:], c.Bytes())
	}

	return bts
}

var ErrNilReceiver = fmt.Errorf("nil receiver")

func (e *ExponentPoly) SetBytes(bts []byte) error {
	if e == nil {
		return ErrNilReceiver
	}

	if len(bts) < 4 {
		return fmt.Errorf("invalid length")
	}
	numCoefs := binary.BigEndian.Uint32(bts[:4])

	if len(bts) != 4+int(numCoefs)*bls12381.G1Size {
		return fmt.Errorf("invalid length")
	}

	e.Coefs = make([]*bls12381.G1, numCoefs)
	for i := 0; i < int(numCoefs); i++ {
		e.Coefs[i] = &bls12381.G1{}

		if err := e.Coefs[i].SetBytes(bts[4+i*bls12381.G1Size : 4+(i+1)*bls12381.G1Size]); err != nil {
			return err
		}
	}

	return nil
}

func (e *ExponentPoly) Equal(exp2 *ExponentPoly) bool {
	if e == nil || exp2 == nil {
		return false
	}

	if len(e.Coefs) != len(exp2.Coefs) {
		return false
	}

	for i := 0; i < len(e.Coefs); i++ {
		if !e.Coefs[i].IsEqual(exp2.Coefs[i]) {
			return false
		}
	}

	return true
}
