package ctap2

import (
	"context"
	"testing"
)

func TestRPIDAllowlistIsExactAndFailClosed(t *testing.T) {
	h := NewHandler(nil, nil, nil, []string{"auth.example.com"})

	if !h.IsRPIDAllowed("auth.example.com") {
		t.Fatal("configured Authentik host was denied")
	}
	for _, value := range []string{"example.com", "evil.auth.example.com", "AUTH.EXAMPLE.COM", ""} {
		if h.IsRPIDAllowed(value) {
			t.Fatalf("unexpectedly allowed RP ID %q", value)
		}
	}
}

func TestOperationsRejectUnconfiguredRPIDBeforeUsingHardware(t *testing.T) {
	h := NewHandler(nil, nil, nil, []string{"auth.example.com"})

	makeStatus, _ := h.MakeCredential(context.Background(), &MakeCredentialRequest{
		RP: PublicKeyCredentialRpEntity{ID: "evil.example.com"},
	})
	if makeStatus != StatusOperationDenied {
		t.Fatalf("MakeCredential status = %#x, want %#x", makeStatus, StatusOperationDenied)
	}

	getStatus, _ := h.GetAssertion(context.Background(), &GetAssertionRequest{
		RPID: "evil.example.com",
	})
	if getStatus != StatusOperationDenied {
		t.Fatalf("GetAssertion status = %#x, want %#x", getStatus, StatusOperationDenied)
	}
}

func TestOperationsRejectSecretDerivationExtension(t *testing.T) {
	h := NewHandler(nil, nil, nil, []string{"auth.example.com"})

	makeStatus, _ := h.MakeCredential(context.Background(), &MakeCredentialRequest{
		RP:         PublicKeyCredentialRpEntity{ID: "auth.example.com"},
		Extensions: map[string]interface{}{"hmac-secret": true},
	})
	if makeStatus != StatusUnsupportedExtension {
		t.Fatalf("MakeCredential status = %#x, want %#x", makeStatus, StatusUnsupportedExtension)
	}

	getStatus, _ := h.GetAssertion(context.Background(), &GetAssertionRequest{
		RPID:       "auth.example.com",
		Extensions: map[string]interface{}{"hmac-secret": map[string]interface{}{}},
	})
	if getStatus != StatusUnsupportedExtension {
		t.Fatalf("GetAssertion status = %#x, want %#x", getStatus, StatusUnsupportedExtension)
	}
}
