// Package auth provides shared client credential validation for proxy inbounds.
package auth

import (
	"errors"
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// ValidateClient checks username/password credentials.
func ValidateClient(client domain.ClientConfig) error {
	if client.Username == "" {
		return errors.New("username is required")
	}
	if client.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// ValidateEnabledClients ensures at least one enabled client passes validation.
func ValidateEnabledClients(clients []domain.ClientConfig, protocolLabel string, validate func(domain.ClientConfig) error) error {
	enabledClients := 0
	for _, c := range clients {
		if !c.Enabled {
			continue
		}
		if err := validate(c); err != nil {
			return fmt.Errorf("client %q: %w", c.Name, err)
		}
		enabledClients++
	}
	if enabledClients == 0 {
		return fmt.Errorf("at least one enabled client is required for %s authentication", protocolLabel)
	}
	return nil
}
