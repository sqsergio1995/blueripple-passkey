package ctap2

import (
	"context"
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/homepalaca/authentik-biometric/userpresence"
)

// Signer is the interface that the TPM or memory backend must implement
type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
}

// Handler handles CTAP2 commands
type Handler struct {
	signer       Signer
	presence     *userpresence.UserPresence
	storage      *CredentialStorage
	allowedRPIDs map[string]struct{}
	aaguid       [16]byte

	// IsPlatform controls GetInfo response:
	//   true  = platform authenticator (plat=true, transports=["internal"])
	//   false = roaming authenticator via HID (plat=false, transports=["usb"])
	IsPlatform bool

	// State for GetNextAssertion
	assertionState *assertionState
}

// assertionState holds state between GetAssertion and GetNextAssertion calls
type assertionState struct {
	credentials    []*CredentialMetadata
	currentIndex   int
	rpIDHash       [32]byte
	clientDataHash []byte
}

// NewHandler creates a new CTAP2 command handler
func NewHandler(signer Signer, presence *userpresence.UserPresence, storage *CredentialStorage, allowedRPIDs []string) *Handler {
	// A stable AAGUID identifies this authenticator implementation without
	// pretending to be certified hardware.
	hash := sha256.Sum256([]byte("authentik-biometric-v1"))
	var aaguid [16]byte
	copy(aaguid[:], hash[:16])

	allowed := make(map[string]struct{}, len(allowedRPIDs))
	for _, rpID := range allowedRPIDs {
		allowed[rpID] = struct{}{}
	}

	return &Handler{
		signer:       signer,
		presence:     presence,
		storage:      storage,
		allowedRPIDs: allowed,
		aaguid:       aaguid,
	}
}

// IsRPIDAllowed applies an exact, fail-closed relying-party allowlist. The
// daemon is intentionally scoped to the user's Authentik host instead of
// silently becoming a general-purpose software security key.
func (h *Handler) IsRPIDAllowed(rpID string) bool {
	_, ok := h.allowedRPIDs[rpID]
	return ok
}

// HandleCommand dispatches a CTAP2 command and returns the status and response
func (h *Handler) HandleCommand(ctx context.Context, cmd byte, data []byte) (status byte, response []byte) {
	log.Printf("CTAP2: Received command 0x%02x, data len=%d", cmd, len(data))

	switch cmd {
	case CmdGetInfo:
		return h.handleGetInfo(ctx)
	case CmdMakeCredential:
		return h.handleMakeCredential(ctx, data)
	case CmdGetAssertion:
		return h.handleGetAssertion(ctx, data)
	case CmdGetNextAssertion:
		return h.handleGetNextAssertion(ctx)
	default:
		log.Printf("CTAP2: Unknown command 0x%02x", cmd)
		return StatusInvalidCommand, nil
	}
}

// CTAP2 requires canonical CBOR encoding with sorted map keys
var ctapEncMode, _ = cbor.EncOptions{
	Sort: cbor.SortCanonical,
}.EncMode()

// handleGetInfo handles authenticatorGetInfo (0x04)
func (h *Handler) handleGetInfo(ctx context.Context) (byte, []byte) {
	resp := h.GetInfo()

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 GetInfo: CBOR encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 GetInfo: Response encoded, %d bytes", len(encoded))
	return StatusSuccess, encoded
}

// handleMakeCredential handles authenticatorMakeCredential (0x01)
func (h *Handler) handleMakeCredential(ctx context.Context, data []byte) (byte, []byte) {
	req, err := parseMakeCredentialRequest(data)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: CBOR decode error: %s", err)
		return StatusInvalidCBOR, nil
	}

	return h.MakeCredential(ctx, req)
}

// handleGetAssertion handles authenticatorGetAssertion (0x02)
func (h *Handler) handleGetAssertion(ctx context.Context, data []byte) (byte, []byte) {
	req, err := parseGetAssertionRequest(data)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: CBOR decode error: %s", err)
		return StatusInvalidCBOR, nil
	}

	return h.GetAssertion(ctx, req)
}

// handleGetNextAssertion handles authenticatorGetNextAssertion (0x08)
// Returns the next credential from a previous GetAssertion that returned multiple matches
func (h *Handler) handleGetNextAssertion(ctx context.Context) (byte, []byte) {
	log.Printf("CTAP2 GetNextAssertion: called")

	if h.assertionState == nil {
		log.Printf("CTAP2 GetNextAssertion: No active assertion state")
		return StatusNotAllowed, nil
	}

	state := h.assertionState
	state.currentIndex++

	if state.currentIndex >= len(state.credentials) {
		log.Printf("CTAP2 GetNextAssertion: No more credentials (index=%d, total=%d)", state.currentIndex, len(state.credentials))
		h.assertionState = nil
		return StatusNotAllowed, nil
	}

	cred := state.credentials[state.currentIndex]
	log.Printf("CTAP2 GetNextAssertion: Returning credential %d of %d for RP=%s", state.currentIndex+1, len(state.credentials), cred.RPID)

	// Build the assertion response for this credential
	return h.buildAssertionResponse(ctx, cred, state.rpIDHash, state.clientDataHash, len(state.credentials), false)
}
