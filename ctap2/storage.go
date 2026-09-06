package ctap2

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CredentialMetadata stores resident key credential information
type CredentialMetadata struct {
	RPID            string    `json:"rp_id"`
	RPName          string    `json:"rp_name,omitempty"`
	UserID          []byte    `json:"user_id"`
	UserName        string    `json:"user_name,omitempty"`
	UserDisplayName string    `json:"user_display_name,omitempty"`
	CredentialID    []byte    `json:"credential_id"`
	PublicKeyX      []byte    `json:"public_key_x"`
	PublicKeyY      []byte    `json:"public_key_y"`
	CreatedAt       time.Time `json:"created_at"`
}

// CredentialStorage manages persistent storage of resident credentials
type CredentialStorage struct {
	mu          sync.RWMutex
	filePath    string
	credentials []*CredentialMetadata
	// In-memory indexes for fast lookup
	byRPID         map[string][]*CredentialMetadata
	byCredentialID map[string]*CredentialMetadata
}

// NewCredentialStorage creates a new credential storage at the given path
func NewCredentialStorage(filePath string) (*CredentialStorage, error) {
	cs := &CredentialStorage{
		filePath:       filePath,
		credentials:    make([]*CredentialMetadata, 0),
		byRPID:         make(map[string][]*CredentialMetadata),
		byCredentialID: make(map[string]*CredentialMetadata),
	}

	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}

	// Load existing credentials if file exists
	if _, err := os.Stat(filePath); err == nil {
		if err := os.Chmod(filePath, 0600); err != nil {
			return nil, err
		}
		if err := cs.load(); err != nil {
			log.Printf("Warning: failed to load credential metadata: %v", err)
			// Continue with empty storage
		}
	}

	return cs, nil
}

// load reads credentials from disk
func (cs *CredentialStorage) load() error {
	data, err := os.ReadFile(cs.filePath)
	if err != nil {
		return err
	}

	var credentials []*CredentialMetadata
	if err := json.Unmarshal(data, &credentials); err != nil {
		return err
	}

	cs.credentials = credentials
	cs.rebuildIndexes()

	log.Printf("CredentialStorage: Loaded %d credentials", len(credentials))
	return nil
}

// save writes credentials to disk
func (cs *CredentialStorage) save() (err error) {
	data, err := json.MarshalIndent(cs.credentials, "", "  ")
	if err != nil {
		return err
	}

	// Write atomically without reusing a potentially permissive stale temp file.
	dir := filepath.Dir(cs.filePath)
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}

	err = os.Rename(tmpPath, cs.filePath)
	return err
}

// rebuildIndexes rebuilds the in-memory lookup indexes
func (cs *CredentialStorage) rebuildIndexes() {
	cs.byRPID = make(map[string][]*CredentialMetadata)
	cs.byCredentialID = make(map[string]*CredentialMetadata)

	for _, cred := range cs.credentials {
		cs.byRPID[cred.RPID] = append(cs.byRPID[cred.RPID], cred)
		cs.byCredentialID[string(cred.CredentialID)] = cred
	}
}

// Save stores a new credential, replacing any existing credential with same user ID for same RP
func (cs *CredentialStorage) Save(cred *CredentialMetadata) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Check if credential with same RPID and UserID already exists
	// Per WebAuthn spec, overwrite existing credential for same user
	found := false
	for i, existing := range cs.credentials {
		if existing.RPID == cred.RPID && bytes.Equal(existing.UserID, cred.UserID) {
			// Replace existing credential
			cs.credentials[i] = cred
			found = true
			log.Printf("CredentialStorage: Replaced credential for RP=%s", cred.RPID)
			break
		}
	}

	if !found {
		cs.credentials = append(cs.credentials, cred)
		log.Printf("CredentialStorage: Added new credential for RP=%s", cred.RPID)
	}

	cs.rebuildIndexes()

	if err := cs.save(); err != nil {
		log.Printf("CredentialStorage: Failed to save: %v", err)
		return err
	}

	return nil
}

// GetByRPID returns all credentials for a given relying party
func (cs *CredentialStorage) GetByRPID(rpId string) []*CredentialMetadata {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	// Return a copy to prevent mutation
	creds := cs.byRPID[rpId]
	if len(creds) == 0 {
		return nil
	}

	result := make([]*CredentialMetadata, len(creds))
	copy(result, creds)
	return result
}

// GetByCredentialID returns a credential by its ID
func (cs *CredentialStorage) GetByCredentialID(credId []byte) *CredentialMetadata {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	return cs.byCredentialID[string(credId)]
}

// Delete removes a credential by its ID
func (cs *CredentialStorage) Delete(credId []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	key := string(credId)
	if _, exists := cs.byCredentialID[key]; !exists {
		return nil // Already deleted or never existed
	}

	// Remove from slice
	newCreds := make([]*CredentialMetadata, 0, len(cs.credentials)-1)
	for _, cred := range cs.credentials {
		if !bytes.Equal(cred.CredentialID, credId) {
			newCreds = append(newCreds, cred)
		}
	}
	cs.credentials = newCreds

	cs.rebuildIndexes()

	if err := cs.save(); err != nil {
		log.Printf("CredentialStorage: Failed to save after delete: %v", err)
		return err
	}

	log.Printf("CredentialStorage: Deleted credential")
	return nil
}

// Count returns the number of stored credentials
func (cs *CredentialStorage) Count() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	return len(cs.credentials)
}

// GetAll returns all stored credentials (for debugging/management)
func (cs *CredentialStorage) GetAll() []*CredentialMetadata {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	result := make([]*CredentialMetadata, len(cs.credentials))
	copy(result, cs.credentials)
	return result
}
