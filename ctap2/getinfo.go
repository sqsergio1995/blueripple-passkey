package ctap2

// GetInfo returns the authenticator capabilities.
// The response varies based on IsPlatform: platform authenticators report
// plat=true with internal transport, while HID authenticators report
// plat=false with usb transport.
func (h *Handler) GetInfo() *GetInfoResponse {
	transport := "usb"
	plat := false
	if h.IsPlatform {
		transport = "internal"
		plat = true
	}

	return &GetInfoResponse{
		// Supported protocol versions
		Versions: []string{"FIDO_2_0"},

		// Keep the authenticator focused: no optional secret-derivation
		// extensions are advertised.
		Extensions: nil,

		// Authenticator identifier
		AAGUID: h.aaguid[:],

		// Authenticator options
		Options: map[string]bool{
			"rk":   true, // Resident keys supported (metadata is stored locally)
			"up":   true, // User presence supported via fingerprint
			"uv":   true, // User verification via fingerprint
			"plat": plat, // Platform vs roaming authenticator
		},

		// Maximum message size
		MaxMsgSize: 1200,

		PinUvAuthProtocols: nil,

		// Maximum credentials in allowList/excludeList
		MaxCredentialCountInList: 8,

		// Maximum credential ID length
		MaxCredentialIdLength: 256,

		// Transport depends on operating mode
		Transports: []string{transport},

		// Supported algorithms
		Algorithms: []PublicKeyCredentialParameters{
			{
				Type: CredentialTypePublicKey,
				Alg:  COSEAlgES256, // -7 = ES256 (ECDSA with P-256 and SHA-256)
			},
		},
	}
}
