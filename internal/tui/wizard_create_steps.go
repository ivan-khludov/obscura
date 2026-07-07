package tui

import "strings"

func (w *wizardState) setCreateTextStep(step createStepID, prompt, hint string, placeholder string) {
	w.createStep = step
	w.stepType = stepText
	w.setPrompt(prompt, hint)
	w.input = newTextInput(placeholder)
}

func (w *wizardState) setCreatePickerStep(step createStepID, prompt, hint string, options, hints []string) {
	w.createStep = step
	w.stepType = stepPicker
	w.setPickerStep(prompt, hint, options, hints)
}

func inferCreateStepFromPrompt(w wizardState) createStepID {
	if strings.HasPrefix(w.prompt, "Port [") {
		return createStepPort
	}
	if strings.HasPrefix(w.prompt, "Subnet [") {
		return createStepWireguardSubnet
	}
	if strings.HasPrefix(w.prompt, "MTU [") {
		return createStepWireguardMTU
	}
	if strings.HasPrefix(w.prompt, "ShadowTLS handshake server [") {
		return createStepShadowTLSHandshake
	}
	if strings.HasPrefix(w.prompt, "Upload bandwidth") {
		return createStepHy2BandwidthUp
	}
	if strings.HasPrefix(w.prompt, "Download bandwidth") {
		return createStepHy2BandwidthDown
	}
	if strings.HasPrefix(w.prompt, "Masquerade proxy URL") {
		return createStepHy2MasqueradeProxy
	}
	if strings.HasPrefix(w.prompt, "Masquerade file directory") {
		return createStepHy2MasqueradeFile
	}
	if strings.Contains(w.prompt, "SNI") || strings.Contains(w.prompt, "Reality handshake") {
		return createStepSNI
	}

	switch w.prompt {
	case "VPN name:":
		return createStepVPNName
	case "Select protocol:":
		return createStepProtocol
	case "Select cipher:":
		return createStepCipher
	case "Enable TLS?":
		return createStepEnableTLS
	case "TLS mode:":
		return createStepTLSMode
	case "uTLS fingerprint:":
		return createStepRealityFingerprint
	case "VLESS flow:":
		return createStepVLESSFlow
	case "Transport options:":
		return createStepTransport
	case "Transport path:":
		return createStepTransportPath
	case "gRPC service name:":
		return createStepTransportServiceName
	case "Transport host:":
		return createStepTransportHost
	case "Fallback port [0=disabled]:", "Fallback port [0=disabled]: (invalid — try again)":
		return createStepFallback
	case "WireGuard interface mode:":
		return createStepWireguardInterface
	case "Congestion control:":
		return createStepTUICCongestion
	case "0-RTT handshake:":
		return createStepTUICZeroRTT
	case "Bandwidth:":
		return createStepHy2Bandwidth
	case "Obfuscation:":
		return createStepHy2Obfs
	case "Masquerade:":
		return createStepHy2Masquerade
	case "Client host [auto]:", "Client host [auto]: (invalid — try again)":
		return createStepClientHost
	case "Client name:":
		return createStepClientName
	}
	return createStepUnknown
}
