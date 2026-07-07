package cmd_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivan-khludov/obscura/internal/cmd"
	"github.com/ivan-khludov/obscura/internal/config"
	"github.com/ivan-khludov/obscura/internal/firewall"
	"github.com/ivan-khludov/obscura/internal/manifest"
	"github.com/ivan-khludov/obscura/internal/orchestration"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/service"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
	"github.com/ivan-khludov/obscura/internal/store"
	"github.com/ivan-khludov/obscura/internal/systemd"
)

func newTestRoot(t *testing.T) (*cobra.Command, context.Context) {
	t.Helper()
	dir := t.TempDir()
	app := &config.App{
		DataDir:      dir,
		DBPath:       filepath.Join(dir, "state.db"),
		ConfigPath:   filepath.Join(dir, "sing-box.json"),
		ManifestPath: filepath.Join(dir, "manifest.json"),
		DevMode:      true,
		ServerHost:   "example.com",
	}
	st, err := store.Open(app.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	man := manifest.NewManager(app.ManifestPath)
	_ = man.Load()
	svc := service.NewService(app, st, runtime.NewProtocolRegistry(), man, firewall.NopFirewall{}, singboxcheck.NopChecker{}, systemd.NopManager{})
	devFlag := true
	root := cmd.NewRootCommand(orchestration.New(svc), app, &devFlag, cmd.Options{DevMode: true})
	return root, context.Background()
}

func runJSONCommand(t *testing.T, root *cobra.Command, ctx context.Context, args ...string) string {
	t.Helper()
	out, err := runCommand(t, root, ctx, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runCommand(t *testing.T, root *cobra.Command, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	root.SetArgs(args)
	execErr := root.ExecuteContext(ctx)
	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), execErr
}

func runCommandWithStdin(t *testing.T, root *cobra.Command, ctx context.Context, stdin string, args ...string) (string, error) {
	t.Helper()
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(inW, stdin); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()
	os.Stdin = inR
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outW
	root.SetArgs(args)
	execErr := root.ExecuteContext(ctx)
	_ = outW.Close()
	os.Stdout = oldStdout
	os.Stdin = oldStdin
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, outR)
	return buf.String(), execErr
}
