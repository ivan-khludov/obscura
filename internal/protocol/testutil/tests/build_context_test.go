package testutil_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/testutil"
)

func TestNewBuildContext(t *testing.T) {
	c := testutil.NewBuildContext("/data")
	if c.ServerHost() != "example.com" || c.DataDir() != "/data" || c.SingBoxBinary() != "sing-box" {
		t.Fatalf("unexpected context: %#v", c)
	}
}

func TestBuildContext_methods(t *testing.T) {
	c := testutil.NewBuildContext("/data")
	c.ServerHostValue = "vpn.example.com"
	c.SingBoxPath = "/usr/bin/sing-box"

	if c.ServerHost() != "vpn.example.com" {
		t.Fatal("ServerHost mismatch")
	}
	if c.DataDir() != "/data" {
		t.Fatal("DataDir mismatch")
	}
	if c.SingBoxBinary() != "/usr/bin/sing-box" {
		t.Fatal("SingBoxBinary mismatch")
	}

	pw, err := c.GeneratePassword(8)
	if err != nil || pw != "test-password" {
		t.Fatalf("GeneratePassword = %q err=%v", pw, err)
	}
	if pw, err = c.GeneratePassword(0); err != nil || pw != "" {
		t.Fatalf("GeneratePassword(0) = %q err=%v", pw, err)
	}

	c.AddCertPath("/etc/cert.pem")
	if len(c.CertPaths) != 1 || c.CertPaths[0] != "/etc/cert.pem" {
		t.Fatalf("CertPaths = %#v", c.CertPaths)
	}

	if err := c.SaveManifest(); err != nil {
		t.Fatal(err)
	}
	if c.ManifestSaves != 1 {
		t.Fatalf("ManifestSaves = %d", c.ManifestSaves)
	}
}
