package service

import (
	"os"
	"os/exec"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
)

// TrojanCreateOptions holds trojan-specific create parameters.
type TrojanCreateOptions = trojan.CreateOptions

// singBoxBinary resolves the sing-box binary path.
func (s *Service) singBoxBinary() string {
	lookPath := exec.LookPath
	if s.lookPathFn != nil {
		lookPath = s.lookPathFn
	}
	if path, err := lookPath("sing-box"); err == nil {
		return path
	}
	return singboxcheck.DefaultBinaryPath
}

// removeTrojanCerts removes generated certificate files and manifest entries.
func (s *Service) removeTrojanCerts(vpn *domain.VPN) {
	if vpn.Protocol != "trojan" {
		return
	}
	data, err := trojan.ParseProtocolData(vpn.ProtocolData)
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

// removeVPNCerts removes generated certificate files and manifest entries.
func (s *Service) removeVPNCerts(vpn *domain.VPN) {
	s.removeHTTPCerts(vpn)
	s.removeTrojanCerts(vpn)
	s.removeVmessCerts(vpn)
	s.removeVlessCerts(vpn)
	s.removeHysteria2Certs(vpn)
	s.removeTUICCerts(vpn)
}
