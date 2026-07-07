package firewall_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/firewall"
)

func ufwMock(run func(ctx context.Context, name string, args ...string) ([]byte, error)) *firewall.Ufw {
	return &firewall.Ufw{RunCommand: run}
}

func TestNopFirewall_AllowPort(t *testing.T) {
	spec, err := firewall.NopFirewall{}.AllowPort(context.Background(), 22, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if spec != "22/tcp" {
		t.Fatalf("spec = %q, want 22/tcp", spec)
	}
}

func TestNopFirewall_DeleteRule(t *testing.T) {
	var fw firewall.NopFirewall
	if err := fw.DeleteRule(context.Background(), "22/tcp"); err != nil {
		t.Fatal(err)
	}
}

func TestNopFirewall_Enable(t *testing.T) {
	var fw firewall.NopFirewall
	if err := fw.Enable(context.Background(), 22); err != nil {
		t.Fatal(err)
	}
}

func TestNopFirewall_IsAvailable(t *testing.T) {
	var fw firewall.NopFirewall
	if fw.IsAvailable() {
		t.Fatal("expected false")
	}
}

func TestNewUfw(t *testing.T) {
	if firewall.NewUfw() == nil {
		t.Fatal("expected non-nil Ufw")
	}
}

func TestUfw_AllowPort_ok(t *testing.T) {
	u := ufwMock(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "ufw" || len(args) != 2 || args[0] != "allow" || args[1] != "1080/tcp" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte("ok\n"), nil
	})
	spec, err := u.AllowPort(context.Background(), 1080, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if spec != "1080/tcp" {
		t.Fatalf("spec = %q, want 1080/tcp", spec)
	}
}

func TestUfw_AllowPort_error(t *testing.T) {
	u := ufwMock(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("denied"), errors.New("failed")
	})
	_, err := u.AllowPort(context.Background(), 1080, "tcp")
	if err == nil || !strings.Contains(err.Error(), "ufw allow 1080/tcp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUfw_AllowPort_default(t *testing.T) {
	u := firewall.NewUfw()
	_, err := u.AllowPort(context.Background(), 1080, "tcp")
	if err == nil {
		t.Fatal("expected error without real ufw")
	}
}

func TestUfw_DeleteRule_ok(t *testing.T) {
	u := ufwMock(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "ufw" || args[0] != "delete" || args[2] != "1080/tcp" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return nil, nil
	})
	if err := u.DeleteRule(context.Background(), "1080/tcp"); err != nil {
		t.Fatal(err)
	}
}

func TestUfw_DeleteRule_notFound(t *testing.T) {
	u := ufwMock(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Could not delete non-existent rule"), errors.New("failed")
	})
	if err := u.DeleteRule(context.Background(), "1080/tcp"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestUfw_DeleteRule_error(t *testing.T) {
	u := ufwMock(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("failed")
	})
	err := u.DeleteRule(context.Background(), "1080/tcp")
	if err == nil || !strings.Contains(err.Error(), "ufw delete allow 1080/tcp") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUfw_Enable_ok(t *testing.T) {
	var calls []string
	u := ufwMock(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	})
	if err := u.Enable(context.Background(), 22); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ufw allow 22/tcp",
		"ufw --force enable",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("call[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestUfw_Enable_allowFails(t *testing.T) {
	u := ufwMock(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("fail"), errors.New("allow failed")
	})
	err := u.Enable(context.Background(), 22)
	if err == nil || !strings.Contains(err.Error(), "ufw allow ssh") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUfw_Enable_enableFails(t *testing.T) {
	u := ufwMock(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ufw" && args[0] == "allow" {
			return nil, nil
		}
		return []byte("enable failed\n"), errors.New("enable failed")
	})
	err := u.Enable(context.Background(), 22)
	if err == nil || !strings.Contains(err.Error(), "ufw enable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUfw_IsAvailable_true(t *testing.T) {
	u := &firewall.Ufw{
		LookPath: func(file string) (string, error) {
			if file == "ufw" {
				return "/usr/sbin/ufw", nil
			}
			return "", errors.New("not found")
		},
	}
	if !u.IsAvailable() {
		t.Fatal("expected true")
	}
}

func TestUfw_IsAvailable_false(t *testing.T) {
	u := &firewall.Ufw{
		LookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
	}
	if u.IsAvailable() {
		t.Fatal("expected false")
	}
}

func TestUfw_IsAvailable_default(t *testing.T) {
	_ = firewall.NewUfw().IsAvailable()
}
