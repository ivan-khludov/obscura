// Package testutil provides test doubles for protocol package tests.
package testutil

// BuildContext is a lightweight protocol.BuildContext test double.
type BuildContext struct {
	ServerHostValue string
	DataDirValue    string
	CertPaths       []string
	ManifestSaves   int
	SingBoxPath     string
}

// NewBuildContext creates a default test context.
func NewBuildContext(dataDir string) *BuildContext {
	return &BuildContext{
		ServerHostValue: "example.com",
		DataDirValue:    dataDir,
		SingBoxPath:     "sing-box",
	}
}

// ServerHost returns the configured public host.
func (c *BuildContext) ServerHost() string {
	return c.ServerHostValue
}

// DataDir returns the data directory path.
func (c *BuildContext) DataDir() string {
	return c.DataDirValue
}

// GeneratePassword returns a deterministic password for tests.
func (c *BuildContext) GeneratePassword(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	return "test-password", nil
}

// AddCertPath records a generated certificate path.
func (c *BuildContext) AddCertPath(path string) {
	c.CertPaths = append(c.CertPaths, path)
}

// SaveManifest tracks manifest persist calls.
func (c *BuildContext) SaveManifest() error {
	c.ManifestSaves++
	return nil
}

// SingBoxBinary returns a configured sing-box binary path.
func (c *BuildContext) SingBoxBinary() string {
	return c.SingBoxPath
}
