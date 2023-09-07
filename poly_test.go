package tibe

import (
	"fmt"
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/stretchr/testify/require"
	"runtime"
	"sync"
	"testing"
)

func TestReconstruction(t *testing.T) {
	// running 1k iterations with random polynomials of degree 5.
	for i := 0; i < 1000; i++ {
		p := NewRandomPoly(5)
		ensurePolyIsNotDegenerate(t, p)

		xy := map[int]*bls12381.Scalar{
			1: p.Eval(1),
			2: p.Eval(2),
			//3: p.Eval(3),
			4: p.Eval(4),
			//5: p.Eval(5),
			6: p.Eval(6),
			//7:  p.Eval(7),
			8: p.Eval(8),
			//9:  p.Eval(9),
			10: p.Eval(10),
		}
		reconstructedSecret := reconstructSecret(xy)
		require.Equal(t, reconstructedSecret.String(), p.Secret().String())
	}
}

func TestReconstructionAdvance(t *testing.T) {
	polyDegree := 60
	p := NewRandomPoly(polyDegree)

	xy := map[int]*bls12381.Scalar{}
	for i := 0; i < 61; i++ {
		xy[2*i+1] = p.Eval(2*i + 1)
	}
	reconstructedSecret := reconstructSecret(xy)
	require.Equal(t, reconstructedSecret.String(), p.Secret().String())

	xy = map[int]*bls12381.Scalar{}
	for i := 0; i < 61; i++ {
		xy[2*i] = p.Eval(2 * i)
	}
	reconstructedSecret = reconstructSecret(xy)
	require.Equal(t, reconstructedSecret.String(), p.Secret().String())

}

func BenchmarkReconstruction(b *testing.B) {
	for d := 0; d < 110; d += 10 {
		b.Run(fmt.Sprintf("reconstricting %d poly", d), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				p := NewRandomPoly(d)
				xy := map[int]*bls12381.Scalar{}
				for i := 0; i < d+1; i++ {
					xy[2*i+1] = p.Eval(2*i + 1)
				}
				b.StartTimer()
				reconstructedSecret := reconstructSecret(xy)
				b.StopTimer()
				require.Equal(b, reconstructedSecret.String(), p.Secret().String())
			}
		})
	}
}

func ensurePolyIsNotDegenerate(t *testing.T, p Poly) {
	for _, scalar := range p.Coeffs() {
		require.False(t, scalar.IsZero() == 1)
	}
}

func TestReconstructSecretInExponent(t *testing.T) {
	q := NewRandomPoly(5)
	shrs := q.CreateShares(10)

	p1 := shrdPkey(t, shrs[0:7], q)
	p2 := shrdPkey(t, shrs[1:8], q)
	p3 := shrdPkey(t, shrs[2:9], q)
	p4 := shrdPkey(t, shrs[3:10], q)

	require.False(t, p1.IsIdentity())
	require.True(t, p1.IsEqual(p2))
	require.True(t, p2.IsEqual(p3))
	require.True(t, p3.IsEqual(p4))

	var splt []PolyShare
	splt = append(splt, shrs[2:5]...)
	splt = append(splt, shrs[0])
	splt = append(splt, shrs[8])
	splt = append(splt, shrs[7])
	splt = append(splt, shrs[9])

	p5 := shrdPkey(t, splt, q)
	require.True(t, p4.IsEqual(p5))

	pk := &bls12381.G1{}
	pk.ScalarMult(q.Secret(), bls12381.G1Generator())
	require.True(t, p5.IsEqual(pk))
}

func shrdPkey(t *testing.T, shrs []PolyShare, p Poly) *bls12381.G1 {
	xys := map[int]*bls12381.G1{}
	indices := make([]int, len(shrs))
	for i, shr := range shrs {
		if i == p.Threshold() {
			break
		}
		pk := &bls12381.G1{}
		pk.ScalarMult(shr.Value, bls12381.G1Generator())
		xys[shr.Index] = pk
		indices[i] = shr.Index
	}

	pk := &bls12381.G1{}
	pk.SetIdentity()

	for i, pk_i := range xys {
		multiplier, err := newLagrangeIndexMultiplier(p.Degree(), i, indices)
		require.NoError(t, err)
		g := &bls12381.G1{}
		g.ScalarMult(multiplier.Value, pk_i)
		pk.Add(pk, g)
	}
	return pk
}

func TestExponentPoly(t *testing.T) {
	p := NewRandomPoly(5)
	exp := p.GetExponentPoly()
	shrs := p.CreateShares(6)

	threads := runtime.NumCPU()

	wg := sync.WaitGroup{}
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				for i := 1; i < 6; i++ {
					shrIndex := i

					pshare := exp.GetPublicShare(uint64(shrIndex))
					pshareComp := bls12381.G1{}
					pshareComp.ScalarMult(shrs[shrIndex-1].Value, bls12381.G1Generator())

					require.True(t, pshareComp.IsEqual(pshare))
				}
			}
		}()
	}

	wg.Wait()
}

func TestMarshalUnmarshalPoly(t *testing.T) {
	p1 := NewRandomPoly(10)
	mrshalled, err := p1.Marshal()
	require.NoError(t, err)

	p2 := &Poly{}
	require.NoError(t, p2.SetBytes(mrshalled))

	require.True(t, p1.Equal(p2))
}

func TestMarshalUnmarshalShare(t *testing.T) {
	p1 := NewRandomPoly(10)
	shr := p1.CreateShares(1)[0]
	mrshalled, err := shr.Marshal()
	require.NoError(t, err)

	shr2 := &PolyShare{}
	require.NoError(t, shr2.SetBytes(mrshalled))

	require.Equal(t, shr.Index, shr2.Index)
	require.True(t, shr.Value.IsEqual(shr2.Value) == 1)
}

func TestMarshalUnmarshalExponentPoly(t *testing.T) {
	p1 := NewRandomPoly(10)
	exp := p1.GetExponentPoly()
	mrshalled := exp.Marshal()

	exp2 := &ExponentPoly{}
	require.NoError(t, exp2.SetBytes(mrshalled))

	require.True(t, exp.Equal(exp2))
}

func BenchmarkExponentPoly_GetPublicShare(b *testing.B) {
	p := NewRandomPoly(50)
	exp := p.GetExponentPoly()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exp.GetPublicShare(uint64(i))
	}
}
