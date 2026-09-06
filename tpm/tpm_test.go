package tpm

import (
	"bytes"
	"testing"
)

func TestPrimaryTemplateDerivationIsStableAndApplicationBound(t *testing.T) {
	seed := []byte("01234567890123456789")
	first := primaryKeyTmpl(seed, []byte("auth.example.com"))
	second := primaryKeyTmpl(seed, []byte("auth.example.com"))
	other := primaryKeyTmpl(seed, []byte("other.example.com"))

	if !bytes.Equal(first.ECCParameters.Point.XRaw, second.ECCParameters.Point.XRaw) ||
		!bytes.Equal(first.ECCParameters.Point.YRaw, second.ECCParameters.Point.YRaw) {
		t.Fatal("primary template derivation is not stable")
	}
	if bytes.Equal(first.ECCParameters.Point.XRaw, other.ECCParameters.Point.XRaw) &&
		bytes.Equal(first.ECCParameters.Point.YRaw, other.ECCParameters.Point.YRaw) {
		t.Fatal("primary template is not bound to the relying party")
	}
}
