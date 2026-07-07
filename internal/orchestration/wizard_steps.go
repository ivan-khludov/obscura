package orchestration

import "github.com/ivan-khludov/obscura/internal/service"

// WizardValidateStep marks which create-VPN wizard step just completed.
type WizardValidateStep = service.WizardValidateStep

// Wizard step markers re-exported from the service layer.
const (
	WizardAfterPort            = service.WizardAfterPort
	WizardAfterTransport       = service.WizardAfterTransport
	WizardAfterTransportDetail = service.WizardAfterTransportDetail
	WizardAfterFallback        = service.WizardAfterFallback
	WizardAfterVlessFlow       = service.WizardAfterVlessFlow
	WizardAfterSNI             = service.WizardAfterSNI
	WizardAfterHy2Bandwidth    = service.WizardAfterHy2Bandwidth
	WizardAfterHy2Masquerade   = service.WizardAfterHy2Masquerade
	WizardAfterWireguardSubnet = service.WizardAfterWireguardSubnet
	WizardAfterWireguardMTU    = service.WizardAfterWireguardMTU
	WizardComplete             = service.WizardComplete
)
