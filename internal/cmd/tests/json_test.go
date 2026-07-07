package cmd_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/cmd"
	"github.com/ivan-khludov/obscura/internal/doctor"
)

func captureStdout(fn func() error) (string, error) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	fnErr := fn()
	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), fnErr
}

func TestPrintOKForTestJSON(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.PrintOKForTest(true, map[string]string{"status": "ok"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result["status"] != "ok" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestPrintOKForTestText(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.PrintOKForTest(false, map[string]string{"status": "ok"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "status:ok") {
		t.Fatalf("unexpected text output: %q", out)
	}
}

func TestOutputClientURIForTestJSONWithClient(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.OutputClientURIForTest(true, map[string]string{"Name": "phone"}, "socks5://x", "", false)
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Client map[string]string `json:"client"`
		URI    string            `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.Client["Name"] != "phone" || result.URI != "socks5://x" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestOutputClientURIForTestJSONURIOnly(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.OutputClientURIForTest(true, nil, "socks5://x", "", false)
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.URI != "socks5://x" {
		t.Fatalf("unexpected uri: %q", result.URI)
	}
}

func TestOutputClientURIForTestText(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.OutputClientURIForTest(false, nil, "socks5://x", "", false)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "socks5://x" {
		t.Fatalf("unexpected text output: %q", out)
	}
}

func TestOutputClientURIForTestTextWithQR(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.OutputClientURIForTest(false, nil, "socks5://x", "socks5://x", true)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "socks5://x") {
		t.Fatalf("expected uri in output: %q", out)
	}
}

func TestPrintQRForTest(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.PrintQRForTest("hello")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "█") {
		t.Fatalf("expected qr ascii art, got %q", out)
	}
}

func TestPrintClientQRForTestDifferentContent(t *testing.T) {
	out, err := captureStdout(func() error {
		return cmd.PrintClientQRForTest("socks5://display", "wireguard-conf-content")
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "socks5://display") {
		t.Fatalf("expected qr from qrContent not display uri, got %q", out)
	}
	if !strings.Contains(out, "█") {
		t.Fatalf("expected qr ascii art, got %q", out)
	}
}

func TestFlagPtrHelpers(t *testing.T) {
	c := &cobra.Command{Use: "test"}
	c.Flags().String("name", "", "")
	c.Flags().Int("port", 0, "")
	c.Flags().Bool("enabled", false, "")
	if err := c.ParseFlags([]string{"--name", "x", "--port", "42", "--enabled"}); err != nil {
		t.Fatal(err)
	}
	if got := cmd.StringPtrFromFlagForTest(c, "name"); got == nil || *got != "x" {
		t.Fatalf("unexpected string ptr: %#v", got)
	}
	if got := cmd.IntPtrFromFlagForTest(c, "port"); got == nil || *got != 42 {
		t.Fatalf("unexpected int ptr: %#v", got)
	}
	if got := cmd.BoolPtrFromFlagForTest(c, "enabled"); got == nil || *got != true {
		t.Fatalf("unexpected bool ptr: %#v", got)
	}
	if cmd.StringPtrFromFlagForTest(c, "missing") != nil {
		t.Fatal("expected nil for unchanged flag")
	}
	if cmd.IntPtrFromFlagForTest(c, "missing") != nil {
		t.Fatal("expected nil for unchanged int flag")
	}
	if cmd.BoolPtrFromFlagForTest(c, "missing") != nil {
		t.Fatal("expected nil for unchanged bool flag")
	}
}

func TestDoctorFormatTextSuccess(t *testing.T) {
	results := []doctor.CheckResult{{Name: "sing-box", Status: doctor.StatusOK, Message: "active"}}
	out, err := captureStdout(func() error {
		return cmd.FormatDoctorResultsForTest(false, results, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "[ok] sing-box: active") {
		t.Fatalf("unexpected doctor text output: %q", out)
	}
}

func TestDoctorFormatJSONError(t *testing.T) {
	results := []doctor.CheckResult{{Name: "sing-box", Status: doctor.StatusFail, Message: "down"}}
	err := cmd.FormatDoctorResultsForTest(true, results, errors.New("doctor found failures"))
	if err == nil {
		t.Fatal("expected json doctor error")
	}
}

func TestDoctorFormatTextError(t *testing.T) {
	results := []doctor.CheckResult{{Name: "sing-box", Status: doctor.StatusFail, Message: "down"}}
	out, err := captureStdout(func() error {
		return cmd.FormatDoctorResultsForTest(false, results, errors.New("doctor found failures"))
	})
	if err == nil {
		t.Fatal("expected doctor text error")
	}
	if !strings.Contains(out, "[fail] sing-box: down") {
		t.Fatalf("unexpected doctor error text: %q", out)
	}
}

func TestDoctorFormatJSONSuccess(t *testing.T) {
	results := []doctor.CheckResult{{Name: "congestion", Status: doctor.StatusOK, Message: "bbr"}}
	out, err := captureStdout(func() error {
		return cmd.FormatDoctorResultsForTest(true, results, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "congestion") {
		t.Fatalf("unexpected doctor json: %q", out)
	}
}
