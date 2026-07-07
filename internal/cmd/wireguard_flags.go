package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type wireguardFlagValues struct {
	orchestration.WireguardCreateOptions
}

// bindWireguardFlags binds CLI flags to command options.
func bindWireguardFlags(cmd *cobra.Command, v *wireguardFlagValues) {
	cmd.Flags().BoolVar(&v.System, "wg-system", false, "Use system WireGuard interface (requires root)")
	cmd.Flags().StringVar(&v.Name, "wg-name", "", "WireGuard interface name")
	cmd.Flags().IntVar(&v.MTU, "wg-mtu", 0, "WireGuard MTU (default: 1408)")
	cmd.Flags().StringSliceVar(&v.Address, "wg-address", nil, "WireGuard tunnel address CIDR (repeatable, default: 10.8.0.1/24)")
	cmd.Flags().StringVar(&v.UDPTimeout, "wg-udp-timeout", "", "WireGuard UDP timeout")
	cmd.Flags().IntVar(&v.Workers, "wg-workers", 0, "WireGuard worker count")
	cmd.Flags().IntVar(&v.PeerPersistentKeepaliveInterval, "wg-peer-keepalive", 0, "Default peer persistent keepalive interval in seconds")
	cmd.Flags().StringVar(&v.PeerPreSharedKey, "wg-peer-psk", "", "Default peer pre-shared key")
	cmd.Flags().IntSliceVar(&v.PeerReserved, "wg-peer-reserved", nil, "Default peer reserved bytes (exactly 3)")
	cmd.Flags().StringSliceVar(&v.ClientAllowedIPs, "wg-client-allowed-ips", nil, "Client AllowedIPs for export (default: 0.0.0.0/0,::/0)")
	cmd.Flags().StringVar(&v.BindInterface, "wg-bind-interface", "", "Bind outbound to network interface")
	cmd.Flags().StringVar(&v.RoutingMark, "wg-routing-mark", "", "Routing mark for outbound connections")
	cmd.Flags().StringVar(&v.ConnectTimeout, "wg-connect-timeout", "", "Connect timeout for outbound")
	cmd.Flags().StringVar(&v.Detour, "wg-detour", "", "Detour tag for outbound")
	cmd.Flags().StringVar(&v.Inet4BindAddress, "wg-inet4-bind-address", "", "IPv4 bind address for outbound")
	cmd.Flags().StringVar(&v.Inet6BindAddress, "wg-inet6-bind-address", "", "IPv6 bind address for outbound")
	cmd.Flags().BoolVar(&v.BindAddressNoPort, "wg-bind-address-no-port", false, "Bind address without port")
	cmd.Flags().BoolVar(&v.ReuseAddr, "wg-reuse-addr", false, "Set SO_REUSEADDR on socket")
	cmd.Flags().StringVar(&v.Netns, "wg-netns", "", "Network namespace for outbound")
	cmd.Flags().BoolVar(&v.TCPFastOpen, "wg-tcp-fast-open", false, "Enable TCP fast open on outbound")
	cmd.Flags().BoolVar(&v.TCPMultiPath, "wg-tcp-multi-path", false, "Enable TCP multipath on outbound")
	cmd.Flags().BoolVar(&v.DisableTCPKeepAlive, "wg-disable-tcp-keep-alive", false, "Disable TCP keepalive on outbound")
	cmd.Flags().StringVar(&v.TCPKeepAlive, "wg-tcp-keep-alive", "", "TCP keepalive interval on outbound")
	cmd.Flags().StringVar(&v.TCPKeepAliveInterval, "wg-tcp-keep-alive-interval", "", "TCP keepalive probe interval on outbound")
	cmd.Flags().BoolVar(&v.UDPFragment, "wg-udp-fragment", false, "Enable UDP fragmentation on outbound")
	cmd.Flags().StringVar(&v.DomainResolver, "wg-domain-resolver", "", "Domain resolver tag for outbound")
	cmd.Flags().StringVar(&v.NetworkStrategy, "wg-network-strategy", "", "Network strategy for outbound")
	cmd.Flags().StringSliceVar(&v.NetworkType, "wg-network-type", nil, "Preferred network types for outbound")
	cmd.Flags().StringSliceVar(&v.FallbackNetworkType, "wg-fallback-network-type", nil, "Fallback network types for outbound")
	cmd.Flags().StringVar(&v.FallbackDelay, "wg-fallback-delay", "", "Fallback network delay for outbound")
}

// readWireguardInput performs an internal helper operation.
func readWireguardInput(v wireguardFlagValues) orchestration.WireguardCreateOptions {
	return v.WireguardCreateOptions
}
