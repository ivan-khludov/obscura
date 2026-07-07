package service_test

import (
	"fmt"
	"testing"

	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/singboxcheck"
)

func TestListProtocols(t *testing.T) {
	svc, _ := newTestService(t)
	protocols := svc.ListProtocols()
	if len(protocols) == 0 {
		t.Fatal("expected registered protocols")
	}
	reg := runtime.NewProtocolRegistry()
	want := reg.List()
	if len(protocols) != len(want) {
		t.Fatalf("got %d protocols, want %d", len(protocols), len(want))
	}
}

func TestGeneratePassword(t *testing.T) {
	svc, _ := newTestService(t)
	pw, err := svc.GeneratePassword(12)
	if err != nil || len(pw) != 12 {
		t.Fatalf("password=%q err=%v", pw, err)
	}
}

func TestSingBoxBinary(t *testing.T) {
	svc, _ := newTestService(t)
	svc.SetLookPathForTest(func(string) (string, error) {
		return "", fmt.Errorf("not found")
	})
	if path := svc.SingBoxBinary(); path != singboxcheck.DefaultBinaryPath {
		t.Fatalf("fallback path=%q", path)
	}
	svc.SetLookPathForTest(func(string) (string, error) {
		return "/custom/sing-box", nil
	})
	if path := svc.SingBoxBinary(); path != "/custom/sing-box" {
		t.Fatalf("look path=%q", path)
	}
	if path := svc.SingBoxBinaryForTest(); path != "/custom/sing-box" {
		t.Fatalf("export path=%q", path)
	}
}

func TestServerHostAndDataDir(t *testing.T) {
	svc, _ := newTestService(t)
	if svc.ServerHost() != "127.0.0.1" {
		t.Fatalf("host=%q", svc.ServerHost())
	}
	if svc.DataDir() == "" {
		t.Fatal("expected data dir")
	}
}

func TestAddCertPathAndSaveManifest(t *testing.T) {
	svc, _ := newTestService(t)
	svc.AddCertPath("/tmp/test.crt")
	if err := svc.SaveManifest(); err != nil {
		t.Fatal(err)
	}
}
