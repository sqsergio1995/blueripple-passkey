package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfiguredRPIDs(t *testing.T) {
	got, err := configuredRPIDs(
		[]string{"LOGIN.EXAMPLE.COM", "auth.example.com"},
		"auth.example.com, login.example.com",
	)
	if err != nil {
		t.Fatalf("configuredRPIDs returned an error: %v", err)
	}
	want := []string{"auth.example.com", "login.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configuredRPIDs = %#v, want %#v", got, want)
	}
}

func TestCredentialStoragePathMigratesLegacyFile(t *testing.T) {
	homeDir := t.TempDir()
	legacyPath := filepath.Join(homeDir, ".local", "share", "authentik-biometric", "credentials.json")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}

	got := credentialStoragePath(homeDir)
	want := filepath.Join(homeDir, ".local", "share", "blueripple-passkey", "credentials.json")
	if got != want {
		t.Fatalf("credentialStoragePath = %q, want %q", got, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("migrated credential file: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy credential file still exists: %v", err)
	}
}

func TestConfiguredRPIDsRejectsUnsafeValues(t *testing.T) {
	for _, value := range []string{
		"https://auth.example.com",
		"auth.example.com/path",
		"*.example.com",
		"auth.example.com:9443",
		"auth example.com",
		"auth..example.com",
		"-auth.example.com",
		"auth_.example.com",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := configuredRPIDs([]string{value}, ""); err == nil {
				t.Fatalf("configuredRPIDs accepted unsafe value %q", value)
			}
		})
	}
}
