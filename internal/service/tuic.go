package service

import (
	"os"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
)

// TUICCreateOptions holds tuic-specific create parameters.
type TUICCreateOptions = tuic.CreateOptions

// removeTUICCerts removes generated certificate files and manifest entries.
func (s *Service) removeTUICCerts(vpn *domain.VPN) {
	if vpn.Protocol != "tuic" {
		return
	}
	data, err := tuic.ParseProtocolData(vpn.ProtocolData)
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
