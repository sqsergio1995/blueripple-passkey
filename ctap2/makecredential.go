package ctap2

import (
	"context"
	"crypto/sha256"
	"log"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MakeCredential handles the authenticatorMakeCredential command
func (h *Handler) MakeCredential(ctx context.Context, req *MakeCredentialRequest) (byte, []byte) {
	log.Printf("CTAP2 MakeCredential: RP=%s", req.RP.ID)
	log.Printf("CTAP2 MakeCredential: Options=%+v", req.Options)
	log.Printf("CTAP2 MakeCredential: Extensions=%+v", req.Extensions)

	if !h.IsRPIDAllowed(req.RP.ID) {
		log.Printf("CTAP2 MakeCredential: denied unconfigured RP=%q", req.RP.ID)
		return StatusOperationDenied, nil
	}
	if _, requested := req.Extensions["hmac-secret"]; requested {
		return StatusUnsupportedExtension, nil
	}

	// Validate clientDataHash
	if len(req.ClientDataHash) != 32 {
		log.Printf("CTAP2 MakeCredential: Invalid clientDataHash length: %d", len(req.ClientDataHash))
		return StatusInvalidParameter, nil
	}

	// Check if at least one supported algorithm is requested
	es256Supported := false
	for _, param := range req.PubKeyCredParams {
		if param.Type == CredentialTypePublicKey && param.Alg == COSEAlgES256 {
			es256Supported = true
			break
		}
	}
	if !es256Supported {
		log.Printf("CTAP2 MakeCredential: ES256 not in requested algorithms")
		return StatusUnsupportedAlgorithm, nil
	}

	// Check excludeList for existing credentials
	rpIDHash := HashRPID(req.RP.ID)
	for _, excluded := range req.ExcludeList {
		// Try to verify if this credential exists by attempting to sign
		dummyHash := sha256.Sum256([]byte("exclude-check"))
		_, err := h.signer.SignASN1(excluded.ID, rpIDHash[:], dummyHash[:])
		if err == nil {
			// Credential exists and is valid - need user presence to confirm exclusion
			log.Printf("CTAP2 MakeCredential: Credential in excludeList exists")
			return StatusCredentialExcluded, nil
		}
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	copy(appParam[:], rpIDHash[:])

	pinResultCh, err := h.presence.ConfirmPresence("Register an authentik passkey for "+req.RP.ID, challengeParam, appParam)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: user presence error: %s", err)
		return StatusOperationDenied, nil
	}

	// Wait for user response with timeout
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if childCtx.Err() != nil {
			return StatusUserActionTimeout, nil
		}
		if !result.OK {
			log.Printf("CTAP2 MakeCredential: User denied or error: %v", result.Error)
			return StatusOperationDenied, nil
		}
	case <-childCtx.Done():
		log.Printf("CTAP2 MakeCredential: User presence timeout")
		return StatusUserActionTimeout, nil
	}

	// Check if resident key is requested
	residentKeyRequested := false
	if req.Options != nil {
		if rk, ok := req.Options["rk"]; ok && rk {
			residentKeyRequested = true
		}
	}

	// Generate credential
	credentialID, x, y, err := h.signer.RegisterKey(rpIDHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredential: RegisterKey error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Generated credential, ID length=%d, residentKey=%v", len(credentialID), residentKeyRequested)

	// Save resident credential if requested
	if residentKeyRequested && h.storage != nil {
		cred := &CredentialMetadata{
			RPID:            req.RP.ID,
			RPName:          req.RP.Name,
			UserID:          req.User.ID,
			UserName:        req.User.Name,
			UserDisplayName: req.User.DisplayName,
			CredentialID:    credentialID,
			PublicKeyX:      bigIntToBytes(x),
			PublicKeyY:      bigIntToBytes(y),
			CreatedAt:       time.Now(),
		}
		if err := h.storage.Save(cred); err != nil {
			log.Printf("CTAP2 MakeCredential: Failed to save resident credential: %s", err)
			// Continue anyway - the credential is still valid, just not discoverable
		}
	}

	// Build COSE public key
	coseKey, err := BuildCOSEPublicKeyES256(x, y)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: COSE key build error: %s", err)
		return StatusOther, nil
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified | FlagAttestedCredData)

	// Build AuthenticatorData
	authData := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     flags,
		SignCount: h.signer.Counter(),
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              h.aaguid,
			CredentialID:        credentialID,
			CredentialPublicKey: coseKey,
		},
	}

	authDataBytes := authData.Marshal()

	// Build attestation signature: sign(authData || clientDataHash)
	toSign := append(authDataBytes, req.ClientDataHash...)
	sigHash := sha256.Sum256(toSign)

	// Use packed self-attestation: the new credential key signs its own
	// attestation. This avoids shipping a shared attestation private key that
	// could misleadingly identify every installation as the same device.
	sig, err := h.signer.SignASN1(credentialID, rpIDHash[:], sigHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredential: Attestation sign error: %s", err)
		return StatusOther, nil
	}

	// Packed self-attestation deliberately omits x5c.
	attStmt := map[string]interface{}{
		"alg": COSEAlgES256,
		"sig": sig,
	}

	// Build response
	resp := &MakeCredentialResponse{
		Fmt:      "packed",
		AuthData: authDataBytes,
		AttStmt:  attStmt,
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// parseMakeCredentialRequest parses the CBOR-encoded MakeCredential request
func parseMakeCredentialRequest(data []byte) (*MakeCredentialRequest, error) {
	var req MakeCredentialRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// bigIntToBytes converts a big.Int to a fixed 32-byte slice (for P-256 coordinates)
func bigIntToBytes(n *big.Int) []byte {
	b := n.Bytes()
	// Pad to 32 bytes if needed
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return padded
	}
	return b
}
