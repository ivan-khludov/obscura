package domain_test

import (
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
)

func TestNormalizeClientHost(t *testing.T) {
	if got := domain.NormalizeClientHost("  host  "); got != "host" {
		t.Fatalf("NormalizeClientHost = %q, want host", got)
	}
}

func TestValidateClientHost(t *testing.T) {
	tests := []struct {
		host      string
		wantErr   bool
		errSubstr string
	}{
		{"", false, ""},
		{"culhackervpn.duckdns.org", false, ""},
		{"1.2.3.4", false, ""},
		{"0.0.0.0", true, "wildcard listen address"},
		{"::", true, "wildcard listen address"},
		{"::0", true, "unspecified address"},
		{"-bad.example.com", true, "invalid client_host"},
	}
	for _, tc := range tests {
		err := domain.ValidateClientHost(domain.NormalizeClientHost(tc.host))
		if tc.wantErr && err == nil {
			t.Fatalf("ValidateClientHost(%q) expected error", tc.host)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("ValidateClientHost(%q): %v", tc.host, err)
		}
		if tc.errSubstr != "" && err != nil && !strings.Contains(err.Error(), tc.errSubstr) {
			t.Fatalf("ValidateClientHost(%q) error = %q, want substring %q", tc.host, err.Error(), tc.errSubstr)
		}
	}
}
