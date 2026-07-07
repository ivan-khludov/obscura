package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/auth"
)

func TestValidateClient_ok(t *testing.T) {
	if err := auth.ValidateClient(domain.ClientConfig{Username: "u", Password: "p"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateClient_missingUsername(t *testing.T) {
	err := auth.ValidateClient(domain.ClientConfig{Password: "p"})
	if err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClient_missingPassword(t *testing.T) {
	err := auth.ValidateClient(domain.ClientConfig{Username: "u"})
	if err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEnabledClients_ok(t *testing.T) {
	clients := []domain.ClientConfig{
		{Name: "a", Username: "u", Password: "p", Enabled: true},
		{Name: "b", Username: "u2", Password: "p2", Enabled: false},
	}
	if err := auth.ValidateEnabledClients(clients, "socks5", auth.ValidateClient); err != nil {
		t.Fatal(err)
	}
}

func TestValidateEnabledClients_validateError(t *testing.T) {
	clients := []domain.ClientConfig{{Name: "bad", Enabled: true}}
	err := auth.ValidateEnabledClients(clients, "socks5", auth.ValidateClient)
	if err == nil || !strings.Contains(err.Error(), `client "bad"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEnabledClients_noneEnabled(t *testing.T) {
	clients := []domain.ClientConfig{{Name: "off", Enabled: false}}
	err := auth.ValidateEnabledClients(clients, "socks5", auth.ValidateClient)
	if err == nil || !strings.Contains(err.Error(), "at least one enabled client") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateEnabledClients_customValidate(t *testing.T) {
	clients := []domain.ClientConfig{{Name: "a", Enabled: true}}
	err := auth.ValidateEnabledClients(clients, "test", func(domain.ClientConfig) error {
		return errors.New("custom")
	})
	if err == nil || !strings.Contains(err.Error(), "custom") {
		t.Fatalf("unexpected error: %v", err)
	}
}
