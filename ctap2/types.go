package ctap2

// GetInfoResponse is the response to authenticatorGetInfo (0x04)
// CTAP2 uses integer keys in CBOR maps
type GetInfoResponse struct {
	Versions                         []string                        `cbor:"1,keyasint"`
	Extensions                       []string                        `cbor:"2,keyasint,omitempty"`
	AAGUID                           []byte                          `cbor:"3,keyasint"`
	Options                          map[string]bool                 `cbor:"4,keyasint,omitempty"`
	MaxMsgSize                       uint                            `cbor:"5,keyasint,omitempty"`
	PinUvAuthProtocols               []uint                          `cbor:"6,keyasint,omitempty"`
	MaxCredentialCountInList         uint                            `cbor:"7,keyasint,omitempty"`
	MaxCredentialIdLength            uint                            `cbor:"8,keyasint,omitempty"`
	Transports                       []string                        `cbor:"9,keyasint,omitempty"`
	Algorithms                       []PublicKeyCredentialParameters `cbor:"10,keyasint,omitempty"`
	MaxSerializedLargeBlobArray      uint                            `cbor:"11,keyasint,omitempty"`
	ForcePINChange                   bool                            `cbor:"12,keyasint,omitempty"`
	MinPINLength                     uint                            `cbor:"13,keyasint,omitempty"`
	FirmwareVersion                  uint                            `cbor:"14,keyasint,omitempty"`
	MaxCredBlobLength                uint                            `cbor:"15,keyasint,omitempty"`
	MaxRPIDsForSetMinPINLength       uint                            `cbor:"16,keyasint,omitempty"`
	PreferredPlatformUvAttempts      uint                            `cbor:"17,keyasint,omitempty"`
	UvModality                       uint                            `cbor:"18,keyasint,omitempty"`
	Certifications                   map[string]int                  `cbor:"19,keyasint,omitempty"`
	RemainingDiscoverableCredentials int                             `cbor:"20,keyasint,omitempty"`
	VendorPrototypeConfigCommands    []uint                          `cbor:"21,keyasint,omitempty"`
}

// PublicKeyCredentialParameters specifies a credential type and algorithm
type PublicKeyCredentialParameters struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

// PublicKeyCredentialRpEntity represents the relying party
type PublicKeyCredentialRpEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

// PublicKeyCredentialUserEntity represents the user
type PublicKeyCredentialUserEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

// PublicKeyCredentialDescriptor identifies a credential
type PublicKeyCredentialDescriptor struct {
	Type       string   `cbor:"type"`
	ID         []byte   `cbor:"id"`
	Transports []string `cbor:"transports,omitempty"`
}

// MakeCredentialRequest is the request for authenticatorMakeCredential (0x01)
type MakeCredentialRequest struct {
	ClientDataHash        []byte                          `cbor:"1,keyasint"`
	RP                    PublicKeyCredentialRpEntity     `cbor:"2,keyasint"`
	User                  PublicKeyCredentialUserEntity   `cbor:"3,keyasint"`
	PubKeyCredParams      []PublicKeyCredentialParameters `cbor:"4,keyasint"`
	ExcludeList           []PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions            map[string]interface{}          `cbor:"6,keyasint,omitempty"`
	Options               map[string]bool                 `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam        []byte                          `cbor:"8,keyasint,omitempty"`
	PinUvAuthProtocol     uint                            `cbor:"9,keyasint,omitempty"`
	EnterpriseAttestation uint                            `cbor:"10,keyasint,omitempty"`
}

// MakeCredentialResponse is the response for authenticatorMakeCredential
type MakeCredentialResponse struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData []byte                 `cbor:"2,keyasint"`
	AttStmt  map[string]interface{} `cbor:"3,keyasint"`
}

// GetAssertionRequest is the request for authenticatorGetAssertion (0x02)
type GetAssertionRequest struct {
	RPID              string                          `cbor:"1,keyasint"`
	ClientDataHash    []byte                          `cbor:"2,keyasint"`
	AllowList         []PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        map[string]interface{}          `cbor:"4,keyasint,omitempty"`
	Options           map[string]bool                 `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam    []byte                          `cbor:"6,keyasint,omitempty"`
	PinUvAuthProtocol uint                            `cbor:"7,keyasint,omitempty"`
}

// GetAssertionResponse is the response for authenticatorGetAssertion
type GetAssertionResponse struct {
	Credential          *PublicKeyCredentialDescriptor `cbor:"1,keyasint,omitempty"`
	AuthData            []byte                         `cbor:"2,keyasint"`
	Signature           []byte                         `cbor:"3,keyasint"`
	User                *PublicKeyCredentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials uint                           `cbor:"5,keyasint,omitempty"`
}
