package cmd

import (
	"context"
	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/doctor"
	"github.com/ivan-khludov/obscura/internal/orchestration"
)

// PrintOKForTest writes v as JSON or Go-syntax text to stdout.
func PrintOKForTest(asJSON bool, v any) error {
	return printOK(asJSON, v)
}

// OutputClientURIForTest prints or encodes a client connection URI and optional QR code.
func OutputClientURIForTest(asJSON bool, client any, uri, qrContent string, showQR bool) error {
	return outputClientURI(asJSON, client, uri, qrContent, showQR)
}

// PrintQRForTest renders content as a terminal QR code to stdout.
func PrintQRForTest(content string) error {
	return printQR(content)
}

// PrintClientQRForTest renders QR content; uses qrContent when it differs from the display URI.
func PrintClientQRForTest(uri, qrContent string) error {
	return printClientQR(uri, qrContent)
}

// StringPtrFromFlagForTest returns a string pointer when the flag was set.
func StringPtrFromFlagForTest(cmd *cobra.Command, name string) *string {
	return stringPtrFromFlag(cmd, name)
}

// IntPtrFromFlagForTest returns an int pointer when the flag was set.
func IntPtrFromFlagForTest(cmd *cobra.Command, name string) *int {
	return intPtrFromFlag(cmd, name)
}

// BoolPtrFromFlagForTest returns a bool pointer when the flag was set.
func BoolPtrFromFlagForTest(cmd *cobra.Command, name string) *bool {
	return boolPtrFromFlag(cmd, name)
}

// FormatDoctorResultsForTest formats doctor check results for CLI output.
func FormatDoctorResultsForTest(jsonOut bool, results []doctor.CheckResult, err error) error {
	return formatDoctorResults(jsonOut, results, err)
}

// FetchClientQRForAddForTest loads QR content during client add.
func FetchClientQRForAddForTest(ctx context.Context, orch *orchestration.Facade, vpnName, name string) (string, error) {
	return fetchClientQRForAdd(ctx, orch, vpnName, name)
}

// ClientAddAfterCreateForTest renders client add output after the client record exists.
func ClientAddAfterCreateForTest(ctx context.Context, orch *orchestration.Facade, jsonOut bool, vpnName, name string, showQR bool, client any, uri string) error {
	return clientAddAfterCreate(ctx, orch, jsonOut, vpnName, name, showQR, client, uri)
}
