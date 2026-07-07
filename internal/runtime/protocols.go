package runtime

import (
	"github.com/ivan-khludov/obscura/internal/protocol"
	"github.com/ivan-khludov/obscura/internal/protocol/httpproxy"
	"github.com/ivan-khludov/obscura/internal/protocol/hysteria2"
	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
	"github.com/ivan-khludov/obscura/internal/protocol/socks5"
	"github.com/ivan-khludov/obscura/internal/protocol/trojan"
	"github.com/ivan-khludov/obscura/internal/protocol/tuic"
	"github.com/ivan-khludov/obscura/internal/protocol/vless"
	"github.com/ivan-khludov/obscura/internal/protocol/vmess"
	"github.com/ivan-khludov/obscura/internal/protocol/wireguard"
)

// NewProtocolRegistry builds explicit protocol registry used by runtime and tests.
func NewProtocolRegistry() *protocol.Registry {
	reg := protocol.NewRegistry()
	reg.Register(&httpproxy.Adapter{})
	reg.Register(&socks5.Adapter{})
	reg.Register(&shadowsocks.Adapter{})
	reg.Register(&trojan.Adapter{})
	reg.Register(&wireguard.Adapter{})
	reg.Register(&vmess.Adapter{})
	reg.Register(&vless.Adapter{})
	reg.Register(&hysteria2.Adapter{})
	reg.Register(&tuic.Adapter{})
	return reg
}
