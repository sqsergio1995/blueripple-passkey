package ctap2

import "testing"

func TestGetInfoDoesNotAdvertiseSecretDerivation(t *testing.T) {
	h := NewHandler(nil, nil, nil, []string{"auth.example.com"})
	info := h.GetInfo()
	if len(info.Extensions) != 0 {
		t.Fatalf("unexpected extensions: %v", info.Extensions)
	}
	if len(info.PinUvAuthProtocols) != 0 {
		t.Fatalf("unexpected PIN/UV protocols: %v", info.PinUvAuthProtocols)
	}
}
