package service

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/certs"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
)

// enableHTTPTLS enables protocol features during VPN setup.
func (s *Service) enableHTTPTLS(vpn *domain.VPN) error {
	if vpn.Protocol != "http" {
		return fmt.Errorf("tls is only supported for http protocol")
	}
	certPath := filepath.Join(s.app.DataDir, "certs", vpn.Tag+".crt")
	keyPath := filepath.Join(s.app.DataDir, "certs", vpn.Tag+".key")
	if err := certs.GenerateSelfSigned(s.app.ServerHost, certPath, keyPath); err != nil {
		return fmt.Errorf("generate tls certificate: %w", err)
	}
	marshal := httpproxy.MarshalProtocolData
	if s.httpMarshal != nil {
		marshal = s.httpMarshal
	}
	data, err := marshal(httpproxy.ProtocolData{
		TLS: true, CertPath: certPath, KeyPath: keyPath,
	})
	if err != nil {
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		return err
	}
	vpn.ProtocolData = data
	s.manifest.AddCertPath(certPath)
	s.manifest.AddCertPath(keyPath)
	_ = s.manifest.Save()
	return nil
}

// disableHTTPTLS performs an internal helper operation.
func (s *Service) disableHTTPTLS(vpn *domain.VPN) {
	s.removeHTTPCerts(vpn)
	vpn.ProtocolData = []byte("{}")
}

// removeHTTPCerts removes generated certificate files and manifest entries.
func (s *Service) removeHTTPCerts(vpn *domain.VPN) {
	if vpn.Protocol != "http" {
		return
	}
	data, err := httpproxy.ParseProtocolData(vpn.ProtocolData)
	if err != nil || !data.TLS {
		return
	}
	for _, path := range []string{data.CertPath, data.KeyPath} {
		if path == "" {
			continue
		}
		_ = os.Remove(path)
		s.manifest.RemoveCertPath(path)
	}
	_ = s.manifest.Save()
}
