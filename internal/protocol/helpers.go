package protocol

import "github.com/ivan-khludov/obscura/internal/domain"

// DefaultFirewallProtos is the default firewall protocol list for inbound VPNs.
var DefaultFirewallProtos = []string{"tcp"}

// ClientQRFromURI returns the same string as ClientURI for protocols without separate QR content.
func ClientQRFromURI(p Protocol, vpn domain.VPNConfig, clients []domain.ClientConfig, client domain.ClientConfig, serverHost string) (string, error) {
	return p.ClientURI(vpn, clients, client, serverHost)
}
