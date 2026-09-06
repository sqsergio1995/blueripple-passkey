package memory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"
)

func TestRegisterAndSign(t *testing.T) {
	signer, err := New()
	if err != nil {
		t.Fatal(err)
	}
	application := sha256.Sum256([]byte("auth.example.com"))
	handle, x, y, err := signer.RegisterKey(application[:])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("challenge"))
	signature, err := signer.SignASN1(handle, application[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.VerifyASN1(&publicKey, digest[:], signature) {
		t.Fatal("signature did not verify")
	}
}

func TestSignRejectsWrongApplicationAndDigestLength(t *testing.T) {
	signer, err := New()
	if err != nil {
		t.Fatal(err)
	}
	application := sha256.Sum256([]byte("auth.example.com"))
	handle, _, _, err := signer.RegisterKey(application[:])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("challenge"))
	otherApplication := sha256.Sum256([]byte("evil.example.com"))
	if _, err := signer.SignASN1(handle, otherApplication[:], digest[:]); err == nil {
		t.Fatal("credential handle was accepted for the wrong relying party")
	}
	if _, err := signer.SignASN1(handle, application[:], digest[:31]); err == nil {
		t.Fatal("short digest was accepted")
	}
}
