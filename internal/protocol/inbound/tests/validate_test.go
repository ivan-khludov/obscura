package inbound_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/inbound"
)

func TestValidateCredentialModes(t *testing.T) {
	if err := inbound.ValidateCredentialModes(false, false, false); err != nil {
		t.Fatal(err)
	}
	if err := inbound.ValidateCredentialModes(true, false, false); err != nil {
		t.Fatal(err)
	}
	err := inbound.ValidateCredentialModes(true, true, false)
	if err == nil || !strings.Contains(err.Error(), "only one TLS credential mode") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := inbound.ValidateCredentialModes(false, true, false); err != nil {
		t.Fatal(err)
	}
	if err := inbound.ValidateCredentialModes(false, false, true); err != nil {
		t.Fatal(err)
	}
	err = inbound.ValidateCredentialModes(false, true, true)
	if err == nil {
		t.Fatal("expected error for acme+cert")
	}
}

func TestValidateCredentialModesNoReality(t *testing.T) {
	if err := inbound.ValidateCredentialModesNoReality(false, true); err != nil {
		t.Fatal(err)
	}
	err := inbound.ValidateCredentialModesNoReality(true, true)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateACMEEmail(t *testing.T) {
	if err := inbound.ValidateACMEEmail(nil); err != nil {
		t.Fatal(err)
	}
	if err := inbound.ValidateACMEEmail(&inbound.ACMEOptions{Domains: []string{"a.com"}, Email: "a@b.com"}); err != nil {
		t.Fatal(err)
	}
	err := inbound.ValidateACMEEmail(&inbound.ACMEOptions{Domains: []string{"a.com"}})
	if err == nil || !strings.Contains(err.Error(), "acme email is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateECH(t *testing.T) {
	if err := inbound.ValidateECH(false, ""); err != nil {
		t.Fatal(err)
	}
	if err := inbound.ValidateECH(true, "/path"); err != nil {
		t.Fatal(err)
	}
	err := inbound.ValidateECH(true, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateCertKeyPair(t *testing.T) {
	if err := inbound.ValidateCertKeyPair("", ""); err != nil {
		t.Fatal(err)
	}
	if err := inbound.ValidateCertKeyPair("/c", "/k"); err != nil {
		t.Fatal(err)
	}
	err := inbound.ValidateCertKeyPair("/c", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateTransport(t *testing.T) {
	http := &inbound.TransportHTTP{Path: "/"}
	ws := &inbound.TransportWS{Path: "/"}
	grpc := &inbound.TransportGRPC{ServiceName: "svc"}
	hu := &inbound.TransportHTTPUpgrade{Path: "/"}
	cases := []struct {
		typ string
		err bool
	}{
		{"", false},
		{"quic", false},
		{"http", false},
		{"ws", false},
		{"grpc", false},
		{"httpupgrade", false},
		{"bad", true},
	}
	for _, tc := range cases {
		var h *inbound.TransportHTTP
		var w *inbound.TransportWS
		var g *inbound.TransportGRPC
		var u *inbound.TransportHTTPUpgrade
		switch tc.typ {
		case "http":
			h = http
		case "ws":
			w = ws
		case "grpc":
			g = grpc
		case "httpupgrade":
			u = hu
		}
		err := inbound.ValidateTransport(tc.typ, h, w, g, u)
		if tc.err && err == nil {
			t.Fatalf("type %q expected error", tc.typ)
		}
		if !tc.err && err != nil {
			t.Fatalf("type %q unexpected error: %v", tc.typ, err)
		}
	}
	for _, tc := range []string{"http", "ws", "grpc", "httpupgrade"} {
		err := inbound.ValidateTransport(tc, nil, nil, nil, nil)
		if err == nil {
			t.Fatalf("expected error for missing %s settings", tc)
		}
	}
}
