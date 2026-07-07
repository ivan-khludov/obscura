package certs_test

import (
	"errors"
	"testing"

	"github.com/ivan-khludov/obscura/internal/certs"
)

func TestNopManager_Issue(t *testing.T) {
	var m certs.NopManager
	err := m.Issue("example.com", "admin@example.com")
	if !errors.Is(err, certs.ErrNotSupported) {
		t.Fatalf("Issue() = %v, want ErrNotSupported", err)
	}
}

func TestNopManager_Renew(t *testing.T) {
	var m certs.NopManager
	err := m.Renew()
	if !errors.Is(err, certs.ErrNotSupported) {
		t.Fatalf("Renew() = %v, want ErrNotSupported", err)
	}
}

func TestNopManager_Remove(t *testing.T) {
	var m certs.NopManager
	err := m.Remove("example.com")
	if !errors.Is(err, certs.ErrNotSupported) {
		t.Fatalf("Remove() = %v, want ErrNotSupported", err)
	}
}
