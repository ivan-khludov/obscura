package service

import (
	"os"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
)

// VLESSCreateOptions holds vless-specific create parameters.
type VLESSCreateOptions = vless.CreateOptions

// removeVlessCerts removes generated certificate files and manifest entries.
func (s *Service) removeVlessCerts(vpn *domain.VPN) {
	if vpn.Protocol != "vless" {
		return
	}
	data, err := vless.ParseProtocolData(vpn.ProtocolData)
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
