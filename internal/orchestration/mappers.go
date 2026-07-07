package orchestration

import (
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/service"
)

func mapVPNView(v domain.VPN) VPNView {
	return VPNView{
		ID:           v.ID,
		Name:         v.Name,
		Protocol:     v.Protocol,
		Tag:          v.Tag,
		Enabled:      v.Enabled,
		ClientHost:   v.ClientHost,
		Listen:       v.Listen,
		ProtocolData: append([]byte(nil), v.ProtocolData...),
		CreatedAt:    v.CreatedAt,
		UpdatedAt:    v.UpdatedAt,
	}
}

func mapClientView(c domain.Client) ClientView {
	return ClientView{
		ID:        c.ID,
		VPNID:     c.VPNID,
		Name:      c.Name,
		Username:  c.Username,
		Password:  c.Password,
		Enabled:   c.Enabled,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

// MapCreateVPNResult converts a service create result into orchestration views.
func MapCreateVPNResult(out *service.CreateVPNResult) *CreateVPNResult {
	if out == nil {
		return nil
	}
	var vpn *VPNView
	if out.VPN != nil {
		value := mapVPNView(*out.VPN)
		vpn = &value
	}
	var client *ClientView
	if out.Client != nil {
		value := mapClientView(*out.Client)
		client = &value
	}
	return &CreateVPNResult{
		VPN:    vpn,
		Client: client,
		URI:    out.URI,
	}
}
