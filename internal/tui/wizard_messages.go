package tui

import (
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

type protocolListMsg struct {
	protocols []string
	err       error
}

type vpnListMsg struct {
	vpns []orchestration.VPNView
	err  error
}

type clientListMsg struct {
	clients []orchestration.ClientView
	err     error
}

type backupListMsg struct {
	backups []orchestration.BackupEntry
	err     error
}

type congestionListMsg struct {
	algorithms []string
	current    string
	err        error
}

type sshPortSetMsg struct {
	port int
	err  error
}

type createVPNResultMsg struct {
	text string
	err  error
}
