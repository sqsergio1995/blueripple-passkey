package memory

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync/atomic"
)

type Mem struct {
	masterPrivateKey []byte
	signCounter      atomic.Uint32
}

func New() (*Mem, error) {
	return &Mem{
		masterPrivateKey: mustRand(32),
	}, nil
}

func (m *Mem) Counter() uint32 {
	return m.signCounter.Add(1)
}

func (m *Mem) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(m.masterPrivateKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (m *Mem) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	curve := elliptic.P256()

	childPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gen key err: %w", err)
	}

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, applicationParam...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	aead, err := m.aead()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create AES-GCM wrapper: %w", err)
	}

	nonce := mustRand(aead.NonceSize())
	encryptedChildPrivateKey := aead.Seal(nil, nonce, childPrivateKey, sum)

	keyHandle := make([]byte, 0, len(nonce)+len(encryptedChildPrivateKey))
	keyHandle = append(keyHandle, nonce...)
	keyHandle = append(keyHandle, encryptedChildPrivateKey...)

	if len(keyHandle) > 255 {
		panic("keyHandle is too big")
	}

	return keyHandle, x, y, nil
}

func (m *Mem) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("invalid SHA-256 digest length: %d", len(digest))
	}

	aead, err := m.aead()
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM wrapper: %w", err)
	}

	if len(keyHandle) < aead.NonceSize() {
		return nil, fmt.Errorf("incorrect size for key handle: %d smaller than nonce", len(keyHandle))
	}
	nonce := keyHandle[:aead.NonceSize()]
	cipherText := keyHandle[aead.NonceSize():]

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, applicationParam[:]...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	childPrivateKey, err := aead.Open(nil, nonce, cipherText, sum)
	if err != nil {
		return nil, fmt.Errorf("open child private key err: %w", err)
	}

	var ecdsaKey ecdsa.PrivateKey

	ecdsaKey.D = new(big.Int).SetBytes(childPrivateKey)
	ecdsaKey.PublicKey.Curve = elliptic.P256()
	ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = ecdsaKey.PublicKey.Curve.ScalarBaseMult(ecdsaKey.D.Bytes())

	return ecdsa.SignASN1(rand.Reader, &ecdsaKey, digest)
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
