package tibe

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryption(t *testing.T) {
	a := require.New(t)
	aeskey := make([]byte, 32)
	msg := make([]byte, 1024)
	_, err := rand.Read(msg)
	a.NoError(err)

	out, err := aesEncrypt(aeskey, msg)
	a.NoError(err)
	a.NotEqual(msg, out)

	dec, err := aesDecrypt(aeskey, out)
	a.NoError(err)

	a.Equal(msg, dec)
}
