package wireguard

import (
	"fmt"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

var keyGenFactory = func() *KeyGen { return &KeyGen{} }

// CreateOptions holds WireGuard-specific create parameters.
type CreateOptions struct {
	System                          bool
	Name                            string
	MTU                             int
	Address                         []string
	UDPTimeout                      string
	Workers                         int
	PeerPreSharedKey                string
	PeerPersistentKeepaliveInterval int
	PeerReserved                    []int
	ClientAllowedIPs                []string
	Detour                          string
	BindInterface                   string
	Inet4BindAddress                string
	Inet6BindAddress                string
	BindAddressNoPort               bool
	RoutingMark                     string
	ReuseAddr                       bool
	Netns                           string
	ConnectTimeout                  string
	TCPFastOpen                     bool
	TCPMultiPath                    bool
	DisableTCPKeepAlive             bool
	TCPKeepAlive                    string
	TCPKeepAliveInterval            string
	UDPFragment                     bool
	DomainResolver                  string
	NetworkStrategy                 string
	NetworkType                     []string
	FallbackNetworkType             []string
	FallbackDelay                   string
}

// BuildProtocolData builds and validates WireGuard protocol data.
func (a *Adapter) BuildProtocolData(_ protocol.BuildContext, spec domain.CreateVPNSpec, _ string, _ protocol.BuildMode) ([]byte, error) {
	opts, err := createOptionsFromSpec(spec)
	if err != nil {
		return nil, err
	}
	data := buildCreateProtocolData(opts)
	pair, err := keyGenFactory().GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate wireguard server keypair: %w", err)
	}
	data.PrivateKey = pair.PrivateKey
	data.PublicKey = pair.PublicKey
	if err := ValidateOptions(data); err != nil {
		return nil, err
	}
	return MarshalProtocolData(data)
}

// NeedsInitialClient reports whether WireGuard requires an enabled client.
func (a *Adapter) NeedsInitialClient(_ domain.VPNConfig) bool {
	return true
}

func createOptionsFromSpec(spec domain.CreateVPNSpec) (CreateOptions, error) {
	switch opts := spec.ProtocolOptions.(type) {
	case nil:
		return CreateOptions{}, nil
	case CreateOptions:
		return opts, nil
	case *CreateOptions:
		if opts == nil {
			return CreateOptions{}, nil
		}
		return *opts, nil
	default:
		return CreateOptions{}, fmt.Errorf("wireguard create options have unexpected type %T", spec.ProtocolOptions)
	}
}

func buildCreateProtocolData(w CreateOptions) ProtocolData {
	data := ProtocolData{
		System:                          w.System,
		Name:                            w.Name,
		MTU:                             w.MTU,
		Address:                         append([]string{}, w.Address...),
		UDPTimeout:                      w.UDPTimeout,
		Workers:                         w.Workers,
		PeerPreSharedKey:                w.PeerPreSharedKey,
		PeerPersistentKeepaliveInterval: w.PeerPersistentKeepaliveInterval,
		PeerReserved:                    append([]int{}, w.PeerReserved...),
		ClientAllowedIPs:                append([]string{}, w.ClientAllowedIPs...),
		Detour:                          w.Detour,
		BindInterface:                   w.BindInterface,
		Inet4BindAddress:                w.Inet4BindAddress,
		Inet6BindAddress:                w.Inet6BindAddress,
		BindAddressNoPort:               w.BindAddressNoPort,
		RoutingMark:                     w.RoutingMark,
		ReuseAddr:                       w.ReuseAddr,
		Netns:                           w.Netns,
		ConnectTimeout:                  w.ConnectTimeout,
		TCPFastOpen:                     w.TCPFastOpen,
		TCPMultiPath:                    w.TCPMultiPath,
		DisableTCPKeepAlive:             w.DisableTCPKeepAlive,
		TCPKeepAlive:                    w.TCPKeepAlive,
		TCPKeepAliveInterval:            w.TCPKeepAliveInterval,
		UDPFragment:                     w.UDPFragment,
		DomainResolver:                  w.DomainResolver,
		NetworkStrategy:                 w.NetworkStrategy,
		NetworkType:                     append([]string{}, w.NetworkType...),
		FallbackNetworkType:             append([]string{}, w.FallbackNetworkType...),
		FallbackDelay:                   w.FallbackDelay,
	}
	if len(data.Address) == 0 {
		data.Address = []string{DefaultAddress}
	}
	return data
}
