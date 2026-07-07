// Package runner provides shared helpers for E2E connect tests against docker compose stacks.
package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// E2E compose service names and default client settings.
const (
	ServerHost             = "e2e-server"
	ShadowTLSHandshakeHost = "handshake"
	TargetURL              = "http://target/"
	ClientName             = "phone"
)

// Config selects an isolated docker compose project and UFW ports for one protocol suite.
type Config struct {
	ProjectName string
	UFWPorts    []int
	UFWUDPPorts []int
}

// Env drives docker compose lifecycle for E2E tests.
type Env struct {
	cfg         Config
	composeFile string
}

// Runner executes VPN operations inside a running compose Env.
type Runner struct {
	*Env
	t *testing.T
}

type vpnCreateResult struct {
	URI string `json:"uri"`
}

// FindRepoRoot locates the repository root from this package.
func FindRepoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// NewEnv returns compose helpers for cfg.
func NewEnv(cfg Config) *Env {
	return &Env{
		cfg:         cfg,
		composeFile: filepath.Join(FindRepoRoot(), "deploy", "e2e", "docker-compose.yml"),
	}
}

// NewRunner returns a Runner bound to a test and env.
func NewRunner(t *testing.T, env *Env) *Runner {
	t.Helper()
	return &Runner{t: t, Env: env}
}

// DockerAvailable reports whether the docker daemon is reachable.
func DockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// RunMain starts compose, bootstraps the server, runs tests, and tears down compose.
func RunMain(cfg Config, m *testing.M) int {
	if !DockerAvailable() {
		fmt.Println("docker not available, skipping e2e tests")
		return 0
	}

	env := NewEnv(cfg)
	if err := env.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "compose up: %v\n", err)
		return 1
	}
	defer func() {
		if err := env.Down(); err != nil {
			fmt.Fprintf(os.Stderr, "compose down: %v\n", err)
		}
	}()

	if err := env.BootstrapServer(); err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap server: %v\n", err)
		return 1
	}

	return m.Run()
}

// Down removes the compose stack for cfg (for manual cleanup targets).
func Down(cfg Config) error {
	env := NewEnv(cfg)
	return env.Down()
}

func (e *Env) compose(args ...string) (string, error) {
	base := []string{"compose", "-f", e.composeFile, "-p", e.cfg.ProjectName}
	cmd := exec.Command("docker", append(base, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err != nil {
		if stderr.Len() > 0 {
			return out, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, stderr.String())
		}
		return out, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// Up builds and starts the E2E compose stack.
func (e *Env) Up() error {
	_, err := e.compose("up", "-d", "--build", "--wait")
	return err
}

// Down stops and removes the E2E compose stack.
func (e *Env) Down() error {
	_, err := e.compose("down", "-v", "--remove-orphans")
	return err
}

func (e *Env) serverExec(env []string, args ...string) (string, error) {
	execArgs := []string{"exec", "-T"}
	for _, pair := range env {
		execArgs = append(execArgs, "-e", pair)
	}
	execArgs = append(execArgs, "e2e-server")
	execArgs = append(execArgs, args...)
	return e.compose(execArgs...)
}

func (e *Env) clientExec(args ...string) (string, error) {
	return e.compose(append([]string{"exec", "-T", "e2e-client"}, args...)...)
}

// resetSingBoxUnit clears systemd start-limit-hit after rapid VPN create/delete cycles.
func (e *Env) resetSingBoxUnit() {
	_, _ = e.serverExec(nil, "systemctl", "reset-failed", "sing-box.service")
}

// BootstrapServer enables ufw, opens cfg ports, and runs obscura bootstrap.
func (e *Env) BootstrapServer() error {
	ports := make([]string, len(e.cfg.UFWPorts))
	for i, p := range e.cfg.UFWPorts {
		ports[i] = strconv.Itoa(p)
	}
	env := []string{"E2E_UFW_PORTS=" + strings.Join(ports, " ")}
	if len(e.cfg.UFWUDPPorts) > 0 {
		udpPorts := make([]string, len(e.cfg.UFWUDPPorts))
		for i, p := range e.cfg.UFWUDPPorts {
			udpPorts[i] = strconv.Itoa(p)
		}
		env = append(env, "E2E_UFW_UDP_PORTS="+strings.Join(udpPorts, " "))
	}
	_, err := e.serverExec(env, "bash", "/usr/local/bin/e2e-bootstrap.sh")
	return err
}

func (r *Runner) vpnCreateJSON(args ...string) (string, error) {
	r.t.Helper()
	out, err := r.serverExec(nil, append([]string{"obscura", "vpn", "create"}, append(args, "--json")...)...)
	if err != nil {
		return "", err
	}
	var result vpnCreateResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return "", fmt.Errorf("parse vpn create json: %w\noutput: %s", err, out)
	}
	if result.URI == "" {
		return "", fmt.Errorf("empty uri in create output: %s", out)
	}
	return result.URI, nil
}

// CreateVPN runs obscura vpn create with the given flags and returns the client URI.
func (r *Runner) CreateVPN(name, protocol string, port int, extra ...string) (string, error) {
	r.t.Helper()
	r.resetSingBoxUnit()
	args := []string{
		"--name", name,
		"--protocol", protocol,
		"--port", strconv.Itoa(port),
		"--client-host", ServerHost,
		"--client-name", ClientName,
	}
	args = append(args, extra...)
	return r.vpnCreateJSON(args...)
}

// DeleteVPN removes a VPN by name.
func (r *Runner) DeleteVPN(name string) error {
	r.t.Helper()
	r.resetSingBoxUnit()
	_, err := r.serverExec(nil, "obscura", "vpn", "delete", name)
	return err
}

// CurlViaProxy fetches TargetURL through the given proxy URI.
func (r *Runner) CurlViaProxy(uri string, insecure bool) error {
	r.t.Helper()
	args := []string{
		"curl", "-sf", "--max-time", "15",
		"--proxy", uri,
		TargetURL,
	}
	if insecure {
		args = append(args, "--proxy-insecure")
	}
	_, err := r.clientExec(args...)
	return err
}
