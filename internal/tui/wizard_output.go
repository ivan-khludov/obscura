package tui

import (
	"github.com/ivan-khludov/obscura/internal/qr"
)

// formatClientExport formats output for display or export.
func formatClientExport(uri, qrContent string) (string, error) {
	content := uri
	if qrContent != "" && qrContent != uri {
		content = qrContent
	}
	ascii, err := qr.Terminal(content)
	if err != nil {
		return uri, nil
	}
	return uri + "\n\n" + ascii, nil
}

// formatURIWithQR formats output for display or export.
func formatURIWithQR(uri string) (string, error) {
	ascii, err := qr.Terminal(uri)
	if err != nil {
		return uri, nil
	}
	return uri + "\n\n" + ascii, nil
}
