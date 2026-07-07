package orchestration

import (
	"fmt"

	"github.com/google/go-cmp/cmp"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// ValidateCreateVPNRequest applies protocol/flag affinity checks before build.
func ValidateCreateVPNRequest(req CreateVPNRequest) error {
	protocolName := req.Protocol
	if protocolName == "" {
		protocolName = string(domain.ProtocolSOCKS5)
	}
	protocolType := domain.ProtocolType(protocolName)

	if req.HTTPTLS && protocolType != domain.ProtocolHTTP {
		return fmt.Errorf("--tls is only supported for http protocol")
	}
	if req.SSMethod != "" && protocolType != domain.ProtocolShadowsocks {
		return fmt.Errorf("--method is only supported for shadowsocks protocol")
	}
	if hasShadowsocksCompat(req) && protocolType != domain.ProtocolShadowsocks {
		return fmt.Errorf("shadowsocks transport options are only supported for shadowsocks protocol")
	}

	multiplexAllowed := protocolType == domain.ProtocolShadowsocks || protocolType == domain.ProtocolTrojan || protocolType == domain.ProtocolVMess || protocolType == domain.ProtocolVLESS
	if (req.MultiplexRequested || req.MultiplexPaddingRequested) && !multiplexAllowed {
		return fmt.Errorf("multiplex is only supported for shadowsocks, trojan, vmess, or vless protocol")
	}
	if req.MultiplexBrutalRequested && protocolType != domain.ProtocolVMess && protocolType != domain.ProtocolVLESS {
		return fmt.Errorf("--multiplex-brutal is only supported for vmess or vless protocol")
	}
	if (req.MultiplexBrutalUpMbpsRequested > 0 || req.MultiplexBrutalDownMbpsRequested > 0) &&
		protocolType != domain.ProtocolVMess && protocolType != domain.ProtocolVLESS {
		return fmt.Errorf("multiplex brutal bandwidth flags are only supported for vmess or vless protocol")
	}

	if hasTrojanOptions(req.Trojan) &&
		protocolType != domain.ProtocolTrojan &&
		protocolType != domain.ProtocolVMess &&
		protocolType != domain.ProtocolVLESS {
		return fmt.Errorf("trojan options are only supported for trojan, vmess, or vless protocol")
	}
	if hasWireguardOptions(req.Wireguard) && protocolType != domain.ProtocolWireGuard {
		return fmt.Errorf("wireguard options are only supported for wireguard protocol")
	}
	if hasHysteria2Options(req.Hysteria2) && protocolType != domain.ProtocolHysteria2 {
		return fmt.Errorf("hysteria2 options are only supported for hysteria2 protocol")
	}
	if hasTUICOptions(req.TUIC) && protocolType != domain.ProtocolTUIC {
		return fmt.Errorf("tuic options are only supported for tuic protocol")
	}

	return nil
}

func hasShadowsocksCompat(req CreateVPNRequest) bool {
	return req.SSPlugin != "" ||
		req.SSPluginOpts != "" ||
		req.SSShadowTLS ||
		req.SSShadowTLSHandshake != "" ||
		req.SSShadowTLSHandshakePort != 0 ||
		req.SSShadowTLSStrictMode
}

func hasTrojanOptions(v TrojanCreateOptions) bool {
	return !cmp.Equal(v, TrojanCreateOptions{})
}

func hasWireguardOptions(v WireguardCreateOptions) bool {
	return !cmp.Equal(v, WireguardCreateOptions{})
}

func hasHysteria2Options(v Hysteria2CreateOptions) bool {
	return !cmp.Equal(v, Hysteria2CreateOptions{})
}

func hasTUICOptions(v TUICCreateOptions) bool {
	return !cmp.Equal(v, TUICCreateOptions{})
}
