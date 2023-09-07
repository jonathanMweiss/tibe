package tibe

import (
	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

// Tests a single player out of N player is able to HIDE some message by using a specific ID.
func TestPlayerHidesAndThenEveryoneVoteToReveal(t *testing.T) {
	a := require.New(t)
	nPlayers := 5
	p := NewRandomPoly(3)
	ps := genPlayers(p, nPlayers, a)
	hiddenMessageId := []byte("RoundIKeys{1,2,3}")
	secretMsg := []byte("hello this is a secret")
	secret, err := ps[0].Hide(hiddenMessageId, secretMsg)
	require.NoError(t, err)

	votes := []Vote{}
	for _, pl := range ps {
		votes = append(votes, pl.Vote(secret.ID))
	}

	// reconstruct the secret:
	msg, err := ps[0].Reveal(votes, secret)
	require.NoError(t, err)
	require.Equal(t, msg, secretMsg)
}

// Tests that a user can HIDE a message by using a specific ID, and the system's PublicKey.
func TestEncryptThenReconstructSKAndDecrypt(t *testing.T) {
	a := require.New(t)
	nPlayers := 5
	p := NewRandomPoly(3)
	ps := genPlayers(p, nPlayers, a)

	uuid := []byte("HELLO")

	symKey, err := createEncryptionKey(uuid, ps[0].SharedPublickey)
	a.NoError(err)
	cipher, err := symKey.encrypt([]byte("secret message"))
	a.NoError(err)
	a.NotEqual(cipher, []byte("secret message"))

	votes := playersVoteOnID(ps, uuid)
	Sk, err := reconstructSecretIbeKey(votes, ps[0].t)
	a.NoError(err)

	msg, err := decrypt(Sk, symKey.ReconstructProperties, cipher)
	a.NoError(err)

	a.Equal(msg, []byte("secret message"))
}

func playersVoteOnID(ps []*Player, ID []byte) []Vote {
	votes := make([]Vote, len(ps))
	for _, player := range ps {
		votes[player.Index-1] = player.Vote(ID)
	}
	return votes
}

func BenchmarkIBEEncryption(b *testing.B) {
	a := require.New(b)
	nPlayers := 5
	p := NewRandomPoly(3)
	ps := genPlayers(p, nPlayers, a)

	Player1IDForRound := []byte("HELLO")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		symKey, err := createEncryptionKey(Player1IDForRound, ps[0].SharedPublickey)
		a.NoError(err)
		cipher, err := symKey.encrypt([]byte("secret message"))
		_, _ = cipher, err
	}
}

func TestValidPublicKeyCreation(t *testing.T) {
	a := require.New(t)
	nPlayers := 5
	p := NewRandomPoly(3)
	ps := genPlayers(p, nPlayers, a)

	sharedSecretKey := p.Secret()
	sharedPublicKey := &bls12381.G1{}
	sharedPublicKey.ScalarMult(sharedSecretKey, bls12381.G1Generator())

	for _, player := range ps {
		a.True(player.SharedPublickey.IsEqual(sharedPublicKey))
	}
}

func TestPublicSignature(t *testing.T) {
	a := require.New(t)
	nPlayers := 5
	p := NewRandomPoly(3)
	pls := genPlayers(p, nPlayers, a)

	ID := []byte("HELLO")
	sigs := make([]Vote, nPlayers)
	for i, pl := range pls {
		sigs[i] = pl.Vote(ID)
	}
	// combine votes:
	combinedSig := &bls12381.G2{}
	combinedSig.SetIdentity()
	tmp := &bls12381.G2{}
	for i := 0; i < p.Threshold(); i++ {
		_ = sigs[i].Sig
		// need to set it up correctly:
		li, err := newLagrangeIndexMultiplier(p.Degree(), sigs[i].Index, []int{1, 2, 3, 4, 5})
		require.NoError(t, err)

		tmp.ScalarMult(li.Value, sigs[i].Sig)
		combinedSig.Add(combinedSig, tmp)
	}

	sigWithSecretKey := g2Hash(ID)
	sigWithSecretKey.ScalarMult(p.Secret(), sigWithSecretKey)

	a.True(combinedSig.IsEqual(sigWithSecretKey))

	// validate that the signature is valid:
	a.True(isValidSignature(ID, combinedSig, pls[0].SharedPublickey))
}

func TestReconstructSecretIbeKey(t *testing.T) {
	a := require.New(t)
	// H(ID)^SK is the secret key, correct?
	// so Having all votes combined over a single hash ID should give me the correct SK.

	p := NewRandomPoly(51)

	nPlayers := p.Degree() * 2
	pls := genPlayers(p, nPlayers, a)
	ID := []byte("HELLO")
	votes := playersVoteOnID(pls, ID)

	ibekey := g2Hash(ID)
	ibekey.ScalarMult(p.Secret(), ibekey)

	reconstructedIbeKey, err := reconstructSecretIbeKey(votes[:p.Threshold()], p.Threshold())
	a.NoError(err)
	a.True(reconstructedIbeKey.IsEqual(ibekey))

	// performing reconstruction with randomly chosen votes.
	t.Run("randomlyChosenVotes", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			// any split over the indices of the polynomial should work..
			// choosing random votes.
			randomIndices := map[int]struct{}{}
			for len(randomIndices) < p.Threshold() {
				pos := rand.Int() % len(votes)
				randomIndices[pos] = struct{}{}
			}

			randomVotes := make([]Vote, 0, p.Threshold())
			for ind := range randomIndices {
				randomVotes = append(randomVotes, votes[ind])
			}

			t.Log("using random votes", randomIndices)
			reconstructedIbeKey, err = reconstructSecretIbeKey(randomVotes, p.Threshold())
			a.NoError(err)
			a.True(reconstructedIbeKey.IsEqual(ibekey))
		}
	})

}

func BenchmarkReconstructionIbeKey(b *testing.B) {
	a := require.New(b)
	p := NewRandomPoly(51)

	nPlayers := p.Degree() * 2
	pls := genPlayers(p, nPlayers, a)
	ID := []byte("HELLO")
	votes := playersVoteOnID(pls, ID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := reconstructSecretIbeKey(votes[:p.Threshold()], p.Threshold())
		a.NoError(err)
	}
}

func genPlayers(p Poly, nPlayers int, a *require.Assertions) []*Player {
	shrs := p.CreateShares(nPlayers)

	pkeys := genPubkeys(nPlayers, shrs)
	ps := make([]*Player, nPlayers)
	for i := range ps {
		p, err := NewPublisher(p.Threshold(), shrs[i], pkeys)
		a.NoError(err)
		ps[i] = p
	}
	return ps
}

func genPubkeys(nPlayers int, shrs []PolyShare) []PublicKey {
	pubkeys := make([]PublicKey, nPlayers)
	//
	for i := range pubkeys {
		pk := &bls12381.G1{}
		pk.ScalarMult(shrs[i].Value, bls12381.G1Generator())
		pubkeys[i] = PublicKey{
			Index: shrs[i].Index,
			G1:    pk,
		}
	}
	return pubkeys
}

func TestVerifyVotes(t *testing.T) {
	a := require.New(t)
	nPlayers := 5
	p := NewRandomPoly(3)
	pls := genPlayers(p, nPlayers, a)

	ID := []byte("HELLO")
	for _, pl := range pls {
		vote := pl.Vote(ID)
		for _, player := range pls {
			a.True(player.Verify(vote))
		}
	}
}
