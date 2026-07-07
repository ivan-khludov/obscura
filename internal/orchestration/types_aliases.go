package orchestration

import (
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
	"github.com/ivan-khludov/obscura/internal/service"
)

// CreateVPNInput is the canonical create input, owned by the service layer.
type CreateVPNInput = service.CreateVPNInput

// UpdateVPNInput is the canonical VPN update input, owned by the service layer.
type UpdateVPNInput = service.UpdateVPNInput

// UpdateClientInput is the canonical client update input, owned by the service layer.
type UpdateClientInput = service.UpdateClientInput

type (
	// HTTPCreateOptions re-exports httpproxy.CreateOptions.
	HTTPCreateOptions = httpproxy.CreateOptions
	// ShadowsocksCreateOptions re-exports shadowsocks.CreateOptions.
	ShadowsocksCreateOptions = shadowsocks.CreateOptions
	// TrojanCreateOptions re-exports trojan.CreateOptions.
	TrojanCreateOptions = trojan.CreateOptions
	// WireguardCreateOptions re-exports wireguard.CreateOptions.
	WireguardCreateOptions = wireguard.CreateOptions
	// VMessCreateOptions re-exports vmess.CreateOptions.
	VMessCreateOptions = vmess.CreateOptions
	// VLESSCreateOptions re-exports vless.CreateOptions.
	VLESSCreateOptions = vless.CreateOptions
	// Hysteria2CreateOptions re-exports hysteria2.CreateOptions.
	Hysteria2CreateOptions = hysteria2.CreateOptions
	// TUICCreateOptions re-exports tuic.CreateOptions.
	TUICCreateOptions = tuic.CreateOptions
)
