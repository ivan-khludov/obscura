// Package qr renders connection URIs as terminal QR codes.
package qr

import (
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// Terminal renders content as an ASCII QR code for terminal display.
func Terminal(content string) (string, error) {
	code, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	ascii := code.ToSmallString(false)
	return strings.TrimRight(ascii, "\n"), nil
}
