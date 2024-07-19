package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()

	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	// Generated manually
	var (
		seed = "07eb0b5353818e7aff4a9ea9d966e50fbd470b22ee9f9a71e201a93360ef3455"
		addressStr = "5d50e03aa503c1a6b8b30bb8d4ce88a91e02c332"
		privKey = newPrivateKeyFromString(seed)
	)

	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}

func TestPrivKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("hello world")

	sig := privKey.Sign(msg)
	assert.True(t, sig.Verify(pubKey, msg))

	// Test with invalid message
	assert.False(t, sig.Verify(pubKey, []byte("bob!")))

	// Test with invalid pubKey
	invalidPrivateKey := GeneratePrivateKey()
	invalidPublicKey := invalidPrivateKey.Public()
	assert.False(t, sig.Verify(invalidPublicKey, msg))
}

func TestPubKeyAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()

	assert.Equal(t, len(address.Bytes()), addressLen)
	fmt.Println(address.Bytes())
	fmt.Println(address)
}
