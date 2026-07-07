package service

import (
	"os"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
)

// Hysteria2CreateOptions holds hysteria2-specific create parameters.
type Hysteria2CreateOptions = hysteria2.CreateOptions

// removeHysteria2Certs removes generated certificate files and manifest entries.
func (s *Service) removeHysteria2Certs(vpn *domain.VPN) {
	if vpn.Protocol != "hysteria2" {
		return
	}
	data, err := hysteria2.ParseProtocolData(vpn.ProtocolData)
	if err != nil {
		return
	}
	for _, path := range []string{data.CertPath, data.KeyPath, data.ECHKeyPath} {
		if path == "" {
			continue
		}
		_ = os.Remove(path)
		s.manifest.RemoveCertPath(path)
	}
	_ = s.manifest.Save()
}
