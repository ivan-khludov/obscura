package orchestration

import (
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// ListenPatch carries optional listen updates for vpn edit.
type ListenPatch struct {
	Listen               *string
	ListenPort           *int
	BindInterface        *string
	RoutingMark          *string
	ReuseAddr            *bool
	Netns                *string
	TCPFastOpen          *bool
	TCPMultiPath         *bool
	DisableTCPKeepAlive  *bool
	TCPKeepAlive         *string
	TCPKeepAliveInterval *string
	UDPFragment          *bool
	UDPTimeout           *string
	Detour               *string
}

// ApplyListenPatch merges patch values into current listen options.
func ApplyListenPatch(current domain.ListenOptions, patch ListenPatch) domain.ListenOptions {
	out := current
	if patch.Listen != nil {
		out.Listen = *patch.Listen
	}
	if patch.ListenPort != nil {
		out.ListenPort = *patch.ListenPort
	}
	if patch.BindInterface != nil {
		out.BindInterface = *patch.BindInterface
	}
	if patch.RoutingMark != nil {
		out.RoutingMark = *patch.RoutingMark
	}
	if patch.ReuseAddr != nil {
		out.ReuseAddr = *patch.ReuseAddr
	}
	if patch.Netns != nil {
		out.Netns = *patch.Netns
	}
	if patch.TCPFastOpen != nil {
		out.TCPFastOpen = *patch.TCPFastOpen
	}
	if patch.TCPMultiPath != nil {
		out.TCPMultiPath = *patch.TCPMultiPath
	}
	if patch.DisableTCPKeepAlive != nil {
		out.DisableTCPKeepAlive = *patch.DisableTCPKeepAlive
	}
	if patch.TCPKeepAlive != nil {
		out.TCPKeepAlive = *patch.TCPKeepAlive
	}
	if patch.TCPKeepAliveInterval != nil {
		out.TCPKeepAliveInterval = *patch.TCPKeepAliveInterval
	}
	if patch.UDPFragment != nil {
		out.UDPFragment = *patch.UDPFragment
	}
	if patch.UDPTimeout != nil {
		out.UDPTimeout = *patch.UDPTimeout
	}
	if patch.Detour != nil {
		out.Detour = *patch.Detour
	}
	return out
}

// BuildEditVPNInput builds UpdateVPNInput for vpn edit flow.
func BuildEditVPNInput(protocol string, req UpdateVPNRequest, tlsEnableRequested, tlsDisableRequested bool) (UpdateVPNInput, error) {
	if tlsEnableRequested || tlsDisableRequested {
		if domain.ProtocolType(protocol) != domain.ProtocolHTTP {
			if tlsEnableRequested {
				return UpdateVPNInput{}, fmt.Errorf("--tls is only supported for http protocol")
			}
			return UpdateVPNInput{}, fmt.Errorf("--no-tls is only supported for http protocol")
		}
	}
	if tlsEnableRequested {
		tlsEnabled := true
		req.HTTPTLS = &tlsEnabled
	}
	if tlsDisableRequested {
		tlsEnabled := false
		req.HTTPTLS = &tlsEnabled
	}
	return BuildUpdateVPNInput(req)
}
