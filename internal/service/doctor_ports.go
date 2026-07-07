package service

import (
	"context"
	"sort"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
)

// buildListenChecks assembles protocol or input data from create parameters.
func (s *Service) buildListenChecks(ctx context.Context) []doctor.ListenCheck {
	vpns, err := s.store.ListEnabledVPNs(ctx)
	if err != nil {
		return nil
	}
	checks := make([]doctor.ListenCheck, 0, len(vpns))
	for _, vpn := range vpns {
		clients, err := s.store.ListClientsByVPN(ctx, vpn.ID)
		if err != nil {
			continue
		}
		enabled := 0
		for _, c := range clients {
			if c.Enabled {
				enabled++
			}
		}
		if enabled == 0 {
			continue
		}
		protos := listenProtosForVPN(vpn)
		checks = append(checks, doctor.ListenCheck{
			VPNName:  vpn.Name,
			Protocol: vpn.Protocol,
			Port:     vpn.Listen.ListenPort,
			Protos:   protos,
		})
	}
	sort.Slice(checks, func(i, j int) bool {
		if checks[i].Port != checks[j].Port {
			return checks[i].Port < checks[j].Port
		}
		return checks[i].VPNName < checks[j].VPNName
	})
	return checks
}

// listenProtosForVPN performs an internal helper operation.
func listenProtosForVPN(vpn domain.VPN) []string {
	switch vpn.Protocol {
	case "hysteria2", "tuic", "wireguard":
		return []string{"udp"}
	case "trojan":
		if trojanTransportIsQUIC(vpn.ProtocolData) {
			return []string{"udp"}
		}
		return []string{"tcp"}
	case "vmess":
		if vmessTransportIsQUIC(vpn.ProtocolData) {
			return []string{"udp"}
		}
		return []string{"tcp"}
	default:
		return []string{"tcp"}
	}
}

// trojanTransportIsQUIC performs an internal helper operation.
func trojanTransportIsQUIC(raw []byte) bool {
	data, err := trojan.ParseProtocolData(raw)
	if err != nil {
		return false
	}
	return data.TransportType == "quic"
}

// vmessTransportIsQUIC performs an internal helper operation.
func vmessTransportIsQUIC(raw []byte) bool {
	data, err := vmess.ParseProtocolData(raw)
	if err != nil {
		return false
	}
	return data.TransportType == "quic"
}
