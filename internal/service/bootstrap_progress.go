package service

import "fmt"

// BootstrapProgress reports bootstrap stage and overall completion (0–100).
type BootstrapProgress struct {
	Label   string
	Percent int
}

func reportBootstrapProgress(opts BootstrapOptions, label string, percent int) {
	if opts.Progress == nil {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	opts.Progress(BootstrapProgress{Label: label, Percent: percent})
}

func formatDownloadProgress(read, total int64) string {
	if total > 0 {
		pct := int(read * 100 / total)
		if pct > 100 {
			pct = 100
		}
		return fmt.Sprintf("Downloading sing-box… %d%% (%s / %s)", pct, formatByteSize(read), formatByteSize(total))
	}
	if read > 0 {
		return fmt.Sprintf("Downloading sing-box… %s", formatByteSize(read))
	}
	return "Downloading sing-box…"
}

func formatByteSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
