package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

// addClient creates a client with generated credentials when omitted.
func (s *Service) addClient(ctx context.Context, in AddClientInput, reapply bool) (*domain.Client, string, error) {
	vpn, err := s.store.GetVPNByName(ctx, in.VPNName)
	if err != nil {
		return nil, "", err
	}
	username := in.Username
	password := in.Password
	if vpn.Protocol == "wireguard" && username == "" && password == "" {
		var err error
		username, password, err = s.generateWireguardClientCredentials()
		if err != nil {
			return nil, "", err
		}
	} else {
		if username == "" && vpn.Protocol != "vmess" && vpn.Protocol != "vless" && vpn.Protocol != "tuic" {
			username = sanitizeName(in.Name)
			if username == "" {
				username = "user-" + uuid.NewString()[:8]
			}
		}
		if username == "" && vpn.Protocol == "tuic" {
			username = uuid.NewString()
		}
		if password == "" {
			var err error
			password, err = s.generateClientPassword(vpn)
			if err != nil {
				return nil, "", err
			}
		}
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return nil, "", err
	}
	clientCfg := domain.ClientConfig{Name: in.Name, Username: username, Password: password, Enabled: true}
	if err := adapter.ValidateClient(clientCfg); err != nil {
		return nil, "", err
	}
	client := &domain.Client{
		VPNID:    vpn.ID,
		Name:     in.Name,
		Username: username,
		Password: password,
		Enabled:  true,
	}
	if err := s.store.CreateClient(ctx, client); err != nil {
		return nil, "", err
	}
	clients, err := s.store.ListClientsByVPN(ctx, vpn.ID)
	if err != nil {
		return nil, "", err
	}
	vpnConfig := toVPNConfig(vpn)
	clientConfigs := toClientConfigs(clients)
	if err := adapter.ValidateVPN(vpnConfig, clientConfigs); err != nil {
		return nil, "", err
	}
	uri, err := adapter.ClientURI(vpnConfig, clientConfigs, clientCfg, s.app.ServerHost)
	if err != nil {
		return nil, "", err
	}
	if reapply {
		if _, err := s.pipeline.Apply(ctx, false); err != nil {
			return nil, "", err
		}
	}
	return client, uri, nil
}

// removeClient deletes a client and reapplies configuration.
func (s *Service) removeClient(ctx context.Context, vpnName, clientName string) error {
	vpn, err := s.store.GetVPNByName(ctx, vpnName)
	if err != nil {
		return err
	}
	client, err := s.store.GetClientByName(ctx, vpn.ID, clientName)
	if err != nil {
		return err
	}
	if !client.Enabled {
		if err := s.store.DeleteClient(ctx, client.ID); err != nil {
			return err
		}
		_, err = s.pipeline.Apply(ctx, false)
		return err
	}
	remaining, err := s.store.ListEnabledClientsByVPN(ctx, vpn.ID)
	if err != nil {
		return err
	}
	enabledRemaining := 0
	for _, c := range remaining {
		if c.ID != client.ID {
			enabledRemaining++
		}
	}
	if vpn.Enabled && enabledRemaining == 0 {
		return fmt.Errorf("cannot remove last enabled client from enabled vpn %q", vpnName)
	}
	if err := s.store.DeleteClient(ctx, client.ID); err != nil {
		return err
	}
	_, err = s.pipeline.Apply(ctx, false)
	return err
}

// listClients returns clients for a VPN.
func (s *Service) listClients(ctx context.Context, vpnName string) ([]domain.Client, error) {
	vpn, err := s.store.GetVPNByName(ctx, vpnName)
	if err != nil {
		return nil, err
	}
	return s.store.ListClientsByVPN(ctx, vpn.ID)
}

// clientURI returns the connection URI for a client.
func (s *Service) clientURI(ctx context.Context, vpnName, clientName string) (string, error) {
	vpn, err := s.store.GetVPNByName(ctx, vpnName)
	if err != nil {
		return "", err
	}
	client, err := s.store.GetClientByName(ctx, vpn.ID, clientName)
	if err != nil {
		return "", err
	}
	clients, err := s.store.ListClientsByVPN(ctx, vpn.ID)
	if err != nil {
		return "", err
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return "", err
	}
	clientCfg := domain.ClientConfig{
		Name: client.Name, Username: client.Username, Password: client.Password, Enabled: client.Enabled,
	}
	return adapter.ClientURI(toVPNConfig(vpn), toClientConfigs(clients), clientCfg, s.app.ServerHost)
}

// clientQRContent returns QR payload for a client (may differ from URI for WireGuard).
func (s *Service) clientQRContent(ctx context.Context, vpnName, clientName string) (string, error) {
	vpn, err := s.store.GetVPNByName(ctx, vpnName)
	if err != nil {
		return "", err
	}
	client, err := s.store.GetClientByName(ctx, vpn.ID, clientName)
	if err != nil {
		return "", err
	}
	clients, err := s.store.ListClientsByVPN(ctx, vpn.ID)
	if err != nil {
		return "", err
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return "", err
	}
	clientCfg := domain.ClientConfig{
		Name: client.Name, Username: client.Username, Password: client.Password, Enabled: client.Enabled,
	}
	return adapter.ClientQRContent(toVPNConfig(vpn), toClientConfigs(clients), clientCfg, s.app.ServerHost)
}

// rotateClientPassword generates a new password for a client.
func (s *Service) rotateClientPassword(ctx context.Context, vpnName, clientName string) (string, string, error) {
	vpn, err := s.store.GetVPNByName(ctx, vpnName)
	if err != nil {
		return "", "", err
	}
	client, err := s.store.GetClientByName(ctx, vpn.ID, clientName)
	if err != nil {
		return "", "", err
	}
	password, err := s.generateClientPassword(vpn)
	if err != nil {
		return "", "", err
	}
	if vpn.Protocol == "wireguard" {
		pub, err := wireguard.PublicKeyFromPrivate(password)
		if err != nil {
			return "", "", err
		}
		client.Username = pub
	}
	client.Password = password
	if err := s.store.UpdateClient(ctx, client); err != nil {
		return "", "", err
	}
	uri, err := s.clientURI(ctx, vpnName, clientName)
	if err != nil {
		return "", "", err
	}
	if _, err := s.pipeline.Apply(ctx, false); err != nil {
		return "", "", err
	}
	return password, uri, nil
}

// updateClient updates an existing client and reapplies configuration when requested.
func (s *Service) updateClient(ctx context.Context, in UpdateClientInput, reapply bool) (*domain.Client, error) {
	vpn, err := s.store.GetVPNByName(ctx, in.VPNName)
	if err != nil {
		return nil, err
	}
	client, err := s.store.GetClientByName(ctx, vpn.ID, in.Name)
	if err != nil {
		return nil, err
	}
	clients, err := s.store.ListClientsByVPN(ctx, vpn.ID)
	if err != nil {
		return nil, err
	}
	if in.NewName != nil {
		if strings.TrimSpace(*in.NewName) == "" {
			return nil, fmt.Errorf("client name is required")
		}
		client.Name = *in.NewName
	}
	if in.Username != nil {
		client.Username = *in.Username
	}
	if in.Password != nil {
		client.Password = *in.Password
	}
	if in.Enabled != nil {
		client.Enabled = *in.Enabled
	}
	adapter, err := s.registry.Get(vpn.Protocol)
	if err != nil {
		return nil, err
	}
	clientCfg := domain.ClientConfig{
		Name: client.Name, Username: client.Username, Password: client.Password, Enabled: client.Enabled,
	}
	if err := adapter.ValidateClient(clientCfg); err != nil {
		return nil, err
	}
	for _, c := range clients {
		if c.ID == client.ID {
			continue
		}
		if c.Name == client.Name {
			return nil, fmt.Errorf("client name %q already exists", client.Name)
		}
		if c.Username == client.Username {
			return nil, fmt.Errorf("username %q already exists", client.Username)
		}
	}
	if in.Enabled != nil && !*in.Enabled && vpn.Enabled {
		enabledRemaining := 0
		for _, c := range clients {
			if c.ID == client.ID {
				continue
			}
			if c.Enabled {
				enabledRemaining++
			}
		}
		if enabledRemaining == 0 {
			return nil, fmt.Errorf("cannot disable last enabled client on enabled vpn %q", in.VPNName)
		}
	}
	updatedClients := make([]domain.ClientConfig, len(clients))
	for i, c := range clients {
		if c.ID == client.ID {
			updatedClients[i] = clientCfg
			continue
		}
		updatedClients[i] = domain.ClientConfig{
			Name: c.Name, Username: c.Username, Password: c.Password, Enabled: c.Enabled,
		}
	}
	if err := adapter.ValidateVPN(toVPNConfig(vpn), updatedClients); err != nil {
		return nil, err
	}
	if err := s.store.UpdateClient(ctx, client); err != nil {
		return nil, err
	}
	if reapply {
		if _, err := s.pipeline.Apply(ctx, false); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// generateClientPassword returns a protocol-appropriate client secret.
func (s *Service) generateClientPassword(vpn *domain.VPN) (string, error) {
	if vpn.Protocol == "shadowsocks" {
		data, err := shadowsocks.ParseProtocolData(vpn.ProtocolData)
		if err != nil {
			return "", err
		}
		method := data.Method
		if method == "" {
			method = shadowsocks.DefaultMethod
		}
		return shadowsocks.GenerateKey(method)
	}
	if vpn.Protocol == "wireguard" {
		pair, err := s.wireguardKeyGen.keypair()
		if err != nil {
			return "", err
		}
		return pair.PrivateKey, nil
	}
	if vpn.Protocol == "vmess" || vpn.Protocol == "vless" {
		return uuid.NewString(), nil
	}
	return s.passwordGen.randomPassword(16)
}
