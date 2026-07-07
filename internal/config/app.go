// Package config holds runtime paths and options for obscura.
package config

import (
	"os"
	"path/filepath"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// App holds resolved paths and feature flags for a running obscura instance.
type App struct {
	DataDir      string
	DBPath       string
	ConfigPath   string
	ManifestPath string
	DevMode      bool
	ServerHost   string
}

// ServerHostFrom resolves the server host from an os.Hostname result.
func ServerHostFrom(host string, err error) string {
	if err != nil || host == "" {
		return "127.0.0.1"
	}
	return host
}

// DefaultApp returns production default paths under /etc/obscura.
func DefaultApp() *App {
	host, err := os.Hostname()
	return &App{
		DataDir:      domain.DefaultDataDir,
		DBPath:       domain.DefaultDBPath,
		ConfigPath:   domain.DefaultSingBoxConfigPath,
		ManifestPath: domain.DefaultManifestPath,
		ServerHost:   ServerHostFrom(host, err),
	}
}

// DevApp returns paths under the user home for local development.
func DevApp() *App {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".obscura")
	return &App{
		DataDir:      base,
		DBPath:       filepath.Join(base, "state.db"),
		ConfigPath:   filepath.Join(base, "sing-box.json"),
		ManifestPath: filepath.Join(base, "manifest.json"),
		DevMode:      true,
		ServerHost:   "127.0.0.1",
	}
}
