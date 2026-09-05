package main

import (
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
