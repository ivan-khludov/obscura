package cmd_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/doctor"
)

func TestDoctorJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "doctor")
	var results []doctor.CheckResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if len(results) < 2 {
		t.Fatalf("expected check results, got %#v", results)
	}
	found := false
	for _, r := range results {
		if r.Name == "congestion" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected congestion check in %#v", results)
	}
}

func TestDoctorText(t *testing.T) {
	root, ctx := newTestRoot(t)
	out, err := runCommand(t, root, ctx, "--dev", "doctor")
	if err == nil {
		t.Fatal("expected doctor text mode to fail on check failures")
	}
	if !strings.Contains(out, "[") {
		t.Fatalf("expected formatted check output, got %q", out)
	}
}

func TestBootstrapYesJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.Status != "bootstrapped" {
		t.Fatalf("unexpected status: %#v", result)
	}
}

func TestBootstrapCancelStdinN(t *testing.T) {
	root, ctx := newTestRoot(t)
	out, err := runCommandWithStdin(t, root, ctx, "n\n", "--dev", "bootstrap")
	if err != nil {
		t.Fatalf("expected cancel to succeed without error, got %v", err)
	}
	if strings.Contains(out, "bootstrapped") {
		t.Fatalf("expected no bootstrap output on cancel, got %q", out)
	}
}

func TestSystemWorkflow(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	runJSONCommand(t, root, ctx, "--dev", "--json", "vpn", "create", "--name", "main", "--port", "1080", "--client-name", "phone")

	applyOut := runJSONCommand(t, root, ctx, "--dev", "--json", "apply")
	var applyResult map[string]any
	if err := json.Unmarshal([]byte(applyOut), &applyResult); err != nil {
		t.Fatalf("apply json: %v\nout=%q", err, applyOut)
	}

	applyText, err := runCommand(t, root, ctx, "--dev", "--json=false", "apply")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(applyText, "ConfigPath") {
		t.Fatalf("unexpected apply text: %q", applyText)
	}

	dryOut := runJSONCommand(t, root, ctx, "--dev", "--json", "apply", "--dry-run")
	if err := json.Unmarshal([]byte(dryOut), &applyResult); err != nil {
		t.Fatalf("apply dry-run json: %v\nout=%q", err, dryOut)
	}
	if applyResult["dry_run"] != true {
		t.Fatalf("expected dry-run result, got %#v", applyResult)
	}

	statusJSON := runJSONCommand(t, root, ctx, "--dev", "--json", "status")
	var status map[string]any
	if err := json.Unmarshal([]byte(statusJSON), &status); err != nil {
		t.Fatalf("status json: %v\nout=%q", err, statusJSON)
	}
	if status["obscura_version"] == nil {
		t.Fatalf("expected status fields, got %#v", status)
	}

	statusText, err := runCommand(t, root, ctx, "--dev", "--json=false", "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusText, "ObscuraVersion:") {
		t.Fatalf("unexpected status text: %q", statusText)
	}

	backupOut := runJSONCommand(t, root, ctx, "--dev", "--json", "backup", "create")
	var backupResult struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(backupOut), &backupResult); err != nil {
		t.Fatalf("backup create json: %v\nout=%q", err, backupOut)
	}
	if backupResult.Path == "" {
		t.Fatal("expected backup path")
	}

	root.SetArgs([]string{"--dev", "backup", "restore", backupResult.Path})
	if err := root.ExecuteContext(ctx); err != nil {
		t.Fatalf("backup restore: %v", err)
	}

	root.SetArgs([]string{"--dev", "rollback"})
	_ = root.ExecuteContext(ctx)

	_, err = runCommand(t, root, ctx, "--dev", "logs")
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
}

func TestUninstallDryRunJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "uninstall", "--dry-run")
	var plan map[string]any
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if plan == nil {
		t.Fatal("expected uninstall plan")
	}
}

func TestUninstallFullConfirmDestroyWipeData(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	root.SetArgs([]string{"--dev", "uninstall", "--full", "--confirm", "destroy", "--wipe-data"})
	if err := root.ExecuteContext(ctx); err != nil {
		t.Fatalf("full uninstall: %v", err)
	}
}

func TestNetworkCongestionListTextJSON(t *testing.T) {
	root, ctx := newTestRoot(t)
	jsonOut := runJSONCommand(t, root, ctx, "--dev", "--json", "network", "congestion", "list")
	var result struct {
		Current   string   `json:"current"`
		Available []string `json:"available"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, jsonOut)
	}
	if result.Current == "" || len(result.Available) == 0 {
		t.Fatalf("unexpected congestion list: %#v", result)
	}

	textOut, err := runCommand(t, root, ctx, "--dev", "--json=false", "network", "congestion", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textOut, "current:") {
		t.Fatalf("unexpected text output: %q", textOut)
	}
}

func TestNetworkCongestionSet(t *testing.T) {
	root, ctx := newTestRoot(t)
	listOut := runJSONCommand(t, root, ctx, "--dev", "--json", "network", "congestion", "list")
	var list struct {
		Current string `json:"current"`
	}
	if err := json.Unmarshal([]byte(listOut), &list); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, listOut)
	}
	setOut := runJSONCommand(t, root, ctx, "--dev", "--json", "network", "congestion", "set", list.Current)
	var setResult struct {
		CongestionControl string `json:"congestion_control"`
	}
	if err := json.Unmarshal([]byte(setOut), &setResult); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, setOut)
	}
	if setResult.CongestionControl != list.Current {
		t.Fatalf("unexpected set result: %#v", setResult)
	}
}

func TestUninstallDryRunText(t *testing.T) {
	root, ctx := newTestRoot(t)
	runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes")
	out, err := runCommand(t, root, ctx, "--dev", "uninstall", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "StopServices") && !strings.Contains(out, "RemoveFiles") {
		t.Fatalf("unexpected dry-run text: %q", out)
	}
}

func TestBootstrapWithFallbackStub(t *testing.T) {
	root, ctx := newTestRoot(t)
	out := runJSONCommand(t, root, ctx, "--dev", "--json", "bootstrap", "--yes", "--with-fallback-stub")
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, out)
	}
	if result.Status != "bootstrapped" {
		t.Fatalf("unexpected status: %#v", result)
	}
}

func TestNetworkCongestionSetText(t *testing.T) {
	root, ctx := newTestRoot(t)
	listOut := runJSONCommand(t, root, ctx, "--dev", "--json", "network", "congestion", "list")
	var list struct {
		Current string `json:"current"`
	}
	if err := json.Unmarshal([]byte(listOut), &list); err != nil {
		t.Fatalf("invalid json: %v\nout=%q", err, listOut)
	}
	out, err := runCommand(t, root, ctx, "--dev", "--json=false", "network", "congestion", "set", list.Current)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "congestion_control") {
		t.Fatalf("unexpected set text: %q", out)
	}
}

func TestBootstrapYesText(t *testing.T) {
	root, ctx := newTestRoot(t)
	out, err := runCommand(t, root, ctx, "--dev", "bootstrap", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "bootstrapped") {
		t.Fatalf("unexpected bootstrap text: %q", out)
	}
}
