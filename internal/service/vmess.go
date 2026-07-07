package service

import (
	"os"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

// VMessCreateOptions holds vmess-specific create parameters.
type VMessCreateOptions = vmess.CreateOptions

// removeVmessCerts removes generated certificate files and manifest entries.
func (s *Service) removeVmessCerts(vpn *domain.VPN) {
	if vpn.Protocol != "vmess" {
		return
	}
	data, err := vmess.ParseProtocolData(vpn.ProtocolData)
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
