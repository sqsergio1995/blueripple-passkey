package ctap2

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialStorageRepairsPermissionsAndSavesAtomically(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}

	storage, err := NewCredentialStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, dir, 0700)
	assertMode(t, path, 0600)

	err = storage.Save(&CredentialMetadata{
		RPID:         "auth.example.com",
		UserID:       []byte("user-id"),
		CredentialID: []byte("credential-id"),
		CreatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, 0600)
	matches, err := filepath.Glob(filepath.Join(dir, ".credentials-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary credential files remained: %v", matches)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
