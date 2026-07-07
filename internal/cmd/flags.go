package cmd

import (
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// bindListenFlags registers all sing-box listen field flags on cmd.
func bindListenFlags(cmd *cobra.Command, listen *domain.ListenOptions) {
	cmd.Flags().StringVar(&listen.Listen, "listen", listen.Listen, "Listen address")
	cmd.Flags().IntVar(&listen.ListenPort, "port", listen.ListenPort, "Listen port")
	cmd.Flags().StringVar(&listen.BindInterface, "bind-interface", listen.BindInterface, "Network interface to bind")
	cmd.Flags().StringVar(&listen.RoutingMark, "routing-mark", listen.RoutingMark, "Netfilter routing mark")
	cmd.Flags().BoolVar(&listen.ReuseAddr, "reuse-addr", listen.ReuseAddr, "Reuse listener address")
	cmd.Flags().StringVar(&listen.Netns, "netns", listen.Netns, "Network namespace")
	cmd.Flags().BoolVar(&listen.TCPFastOpen, "tcp-fast-open", listen.TCPFastOpen, "Enable TCP fast open")
	cmd.Flags().BoolVar(&listen.TCPMultiPath, "tcp-multi-path", listen.TCPMultiPath, "Enable TCP multipath")
	cmd.Flags().BoolVar(&listen.DisableTCPKeepAlive, "disable-tcp-keep-alive", listen.DisableTCPKeepAlive, "Disable TCP keep alive")
	cmd.Flags().StringVar(&listen.TCPKeepAlive, "tcp-keep-alive", listen.TCPKeepAlive, "TCP keep alive period")
	cmd.Flags().StringVar(&listen.TCPKeepAliveInterval, "tcp-keep-alive-interval", listen.TCPKeepAliveInterval, "TCP keep alive interval")
	cmd.Flags().BoolVar(&listen.UDPFragment, "udp-fragment", listen.UDPFragment, "Enable UDP fragmentation")
	cmd.Flags().StringVar(&listen.UDPTimeout, "udp-timeout", listen.UDPTimeout, "UDP NAT expiration time")
	cmd.Flags().StringVar(&listen.Detour, "detour", listen.Detour, "Detour inbound tag")
}
