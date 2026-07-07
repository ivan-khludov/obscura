package wireguard

import (
	"fmt"
	"strings"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol/listen"
)

// RenderClientConf builds a WireGuard .conf file for the client.
func RenderClientConf(vpn domain.VPNConfig, data ProtocolData, client domain.ClientConfig, serverHost string, clientAddress string) string {
	host := listen.ProxyHost(vpn, serverHost)
	mtu := data.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	keepalive := data.PeerPersistentKeepaliveInterval
	if keepalive == 0 {
		keepalive = DefaultPeerKeepalive
	}
	allowed := ClientAllowedIPs(data)
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", client.Password)
	fmt.Fprintf(&b, "Address = %s\n", clientAddress)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	fmt.Fprintf(&b, "DNS = 1.1.1.1\n")
	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", data.PublicKey)
	if data.PeerPreSharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", data.PeerPreSharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", host, vpn.Listen.ListenPort)
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)
	return b.String()
}
