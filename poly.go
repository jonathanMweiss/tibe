package tibe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/ecc/bls12381"
	"io"
	"sort"
	"sync"
)

// Poly is a polynomial of degree n.
type Poly struct {
	Coefs []*bls12381.Scalar
}

// PolyShare is a specific share of a polynomial P(i).
type PolyShare struct {
	Index int
	Value *bls12381.Scalar
}

func (p PolyShare) Marshal() ([]byte, error) {
	bts, err := p.Value.MarshalBinary()
	if err != nil {
		return nil, err
	}

	bf := make([]byte, len(bts)+4)
	binary.BigEndian.PutUint32(bf, uint32(p.Index))
	copy(bf[4:], bts)
	return bf, nil
}

func (p *PolyShare) SetBytes(bts []byte) error {
	if len(bts) < 4+bls12381.ScalarSize {
		return fmt.Errorf("invalid share")
	}

	p.Index = int(binary.BigEndian.Uint32(bts))

	p.Value = &bls12381.Scalar{}
	return p.Value.UnmarshalBinary(bts[4:])
}

func (p *PolyShare) ComputePublicKey() PublicKey {
	pkey := &bls12381.G1{}
	pkey.ScalarMult(p.Value, bls12381.G1Generator())
	return PublicKey{
		Index: p.Index,
		G1:    pkey,
	}
}

// NewRandomPoly returns a new polynomial with a random secret and random coefficients.
func NewRandomPoly(degree int, reader ...io.Reader) Poly {
	if len(reader) == 0 {
		reader = []io.Reader{rand.Reader}
	}

	coefs := make([]*bls12381.Scalar, degree+1)

	for i := range coefs {
		ai := &bls12381.Scalar{}
		if err := ai.Random(reader[0]); err != nil {
			panic(err)
		}

		coefs[i] = ai
	}

	return Poly{Coefs: coefs}
}

// Degree states the degree of the polynomial.
func (p *Poly) Degree() int {
	return len(p.Coefs)
}

// Threshold states the minimum number of shares required to reconstruct the secret.
func (p *Poly) Threshold() int {
	return len(p.Coefs) + 1
}

// Coeffs returns a copy of the coefficients of the polynomial.
func (p *Poly) Coeffs() []*bls12381.Scalar {
	return p.Copy().Coefs
}

// Secret returns the secret value of the polynomial, that is P(0).
func (p *Poly) Secret() *bls12381.Scalar {
	s := &bls12381.Scalar{}
	s.Set(p.Coefs[0])

	return s
}

// Eval Evaluates the polynomial P for a given i: P(i).
func (p *Poly) Eval(i int) *bls12381.Scalar {
	xi := &bls12381.Scalar{}
	xi.SetUint64(uint64(i))

	v := &bls12381.Scalar{}
	v.SetUint64(0)

	for j := len(p.Coefs) - 1; j >= 0; j-- {
		v.Mul(v, xi)
		v.Add(v, p.Coefs[j])
	}

	return v
}

// CreateShares creates a set of shares for the polynomial. these shares are secret values
// and should be treated with care.
func (p *Poly) CreateShares(n int) []PolyShare {
	shrs := make([]PolyShare, n)
	for j := 1; j < n+1; j++ {
		shrs[j-1] = PolyShare{
			Index: j,
			Value: p.Eval(j),
		}
	}

	return shrs
}

// GetExponentPoly returns the poly in an exponent form: [a0,a1,a2,...] turns into [g^a0, g^a1, g^a2,...]
func (p *Poly) GetExponentPoly() *ExponentPoly {
	ep := &ExponentPoly{
		Coefs: make([]*bls12381.G1, p.Degree()),
		cache: sync.Map{},
	}

	for i := range ep.Coefs {
		ep.Coefs[i] = &bls12381.G1{}
		ep.Coefs[i].ScalarMult(p.Coefs[i], bls12381.G1Generator())
	}

	return ep
}

// Copy returns a copy of the polynomial.
func (p *Poly) Copy() *Poly {
	cpy := &Poly{make([]*bls12381.Scalar, len(p.Coefs))}
	for i := range p.Coefs {
		cpy.Coefs[i] = &bls12381.Scalar{}
		cpy.Coefs[i].Set(p.Coefs[i])
	}

	return cpy
}

func (p *Poly) Marshal() ([]byte, error) {
	if p == nil {
		return nil, ErrNilReceiver
	}
	numCoeffs := len(p.Coefs)

	bf := make([]byte, 4, 4+numCoeffs*bls12381.ScalarSize)
	binary.BigEndian.PutUint32(bf, uint32(numCoeffs))

	for _, c := range p.Coefs {
		bts, err := c.MarshalBinary()
		if err != nil {
			return nil, err
		}

		bf = append(bf, bts...)
	}
	return bf, nil
}

func (p *Poly) SetBytes(mrshalled []byte) error {
	if p == nil {
		return ErrNilReceiver
	}

	if len(mrshalled) < 4 {
		return fmt.Errorf("invalid marshalled polynomial")
	}

	numCoeffs := int(binary.BigEndian.Uint32(mrshalled))
	p.Coefs = make([]*bls12381.Scalar, numCoeffs)

	if len(mrshalled) != 4+numCoeffs*bls12381.ScalarSize {
		return fmt.Errorf("invalid marshalled polynomial")
	}

	for i := 0; i < numCoeffs; i++ {
		p.Coefs[i] = &bls12381.Scalar{}
		p.Coefs[i].SetBytes(mrshalled[4+i*bls12381.ScalarSize : 4+(i+1)*bls12381.ScalarSize])
	}

	return nil
}

func (p *Poly) Equal(p2 *Poly) bool {
	if p == nil || p2 == nil {
		return false
	}

	if p.Degree() != p2.Degree() {
		return false
	}

	for i := range p.Coefs {
		if p.Coefs[i].IsEqual(p2.Coefs[i]) != 1 {
			return false
		}
	}

	return true
}

type lagrangeIndexMultiplier struct {
	I      int // index of holder, 0 <= I < N. will compute \ell_0
	Degree int // degree of polynomial
	Value  *bls12381.Scalar
}

func newLagrangeIndexMultiplier(degree, index int, indices []int) (*lagrangeIndexMultiplier, error) {
	xs := map[int]struct{}{}
	for _, i := range indices {
		xs[i] = struct{}{}
	}

	if len(xs) < degree+1 {
		return nil, fmt.Errorf("missing %d points", degree+1-len(xs))
	}

	inds := make([]int, 0, len(xs))
	for ind := range xs {
		inds = append(inds, ind)
	}

	sort.Ints(inds)
	inds = inds[:degree+1]

	return &lagrangeIndexMultiplier{
		I:      index,
		Degree: degree,
		Value:  computeLagrangeIndexMultiplier(inds, index),
	}, nil
}

func reconstructSecret(xy map[int]*bls12381.Scalar) *bls12381.Scalar {
	nom := &bls12381.Scalar{}
	denom := &bls12381.Scalar{}

	acc := &bls12381.Scalar{}
	acc.SetUint64(0)

	tmp := &bls12381.Scalar{}
	tmpidx := &bls12381.Scalar{}

	for xi, yi := range xy {
		nom.Set(yi)
		denom.SetUint64(1)
		tmp.SetUint64(uint64(xi))

		for xj := range xy {
			if xj == xi {
				continue
			}

			tmpidx.SetUint64(uint64(xj)) // using xj-0 as nominator.
			nom.Mul(nom, tmpidx)

			tmpidx.Sub(tmpidx, tmp)
			denom.Mul(denom, tmpidx)
		}

		denom.Inv(denom)
		nom.Mul(nom, denom)
		acc.Add(acc, nom)
	}

	return acc
}

func computeLagrangeIndexMultiplier(indices []int, index int) *bls12381.Scalar {
	nom := &bls12381.Scalar{}
	nom.SetUint64(1)

	denom := &bls12381.Scalar{}
	denom.SetUint64(1)

	indx := &bls12381.Scalar{}
	indx.SetUint64(uint64(index))

	tmp := &bls12381.Scalar{} // created once, reused throughout the for-loop.
	for _, xj := range indices {
		if xj == index {
			continue
		}

		tmp.SetUint64(uint64(xj)) // using xj-0 as nominator.
		nom.Mul(nom, tmp)

		tmp.Sub(tmp, indx)
		denom.Mul(denom, tmp)
	}

	// nom/denom:
	denom.Inv(denom)
	nom.Mul(nom, denom)

	return nom
}
