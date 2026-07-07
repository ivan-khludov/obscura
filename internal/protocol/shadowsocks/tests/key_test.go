package shadowsocks_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/protocol/shadowsocks"
)

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("rand failed") }

func TestGenerateKey_unsupportedMethod(t *testing.T) {
	gen := &shadowsocks.KeyGen{}
	if _, err := gen.GenerateKey("unknown"); err == nil {
		t.Fatal("expected unsupported method error")
	}
}

func TestGenerateKey_packageFunc(t *testing.T) {
	for _, method := range shadowsocks.Methods {
		t.Run(method, func(t *testing.T) {
			key, err := shadowsocks.GenerateKey(method)
			if err != nil {
				t.Fatal(err)
			}
			if err := shadowsocks.ValidateKey(method, key); err != nil {
				t.Fatal(err)
			}
			wantLen, _ := shadowsocks.KeyLength(method)
			raw, _ := base64.StdEncoding.DecodeString(key)
			if len(raw) != wantLen {
				t.Fatalf("expected %d bytes, got %d", wantLen, len(raw))
			}
		})
	}
}

func TestKeyGen_nilReceiver(t *testing.T) {
	var gen *shadowsocks.KeyGen
	key, err := gen.GenerateKey("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	if err := shadowsocks.ValidateKey("2022-blake3-aes-128-gcm", key); err != nil {
		t.Fatal(err)
	}
}

func TestKeyGen_randError(t *testing.T) {
	gen := &shadowsocks.KeyGen{RandRead: failReader{}}
	_, err := gen.GenerateKey("2022-blake3-aes-128-gcm")
	if err == nil || !strings.Contains(err.Error(), "generate key") {
		t.Fatalf("expected rand error, got %v", err)
	}
}

func TestKeyLength(t *testing.T) {
	if n, err := shadowsocks.KeyLength("2022-blake3-aes-128-gcm"); err != nil || n != 16 {
		t.Fatalf("aes-128 length = %d, %v", n, err)
	}
	if n, err := shadowsocks.KeyLength("2022-blake3-aes-256-gcm"); err != nil || n != 32 {
		t.Fatalf("aes-256 length = %d, %v", n, err)
	}
	if n, err := shadowsocks.KeyLength("2022-blake3-chacha20-poly1305"); err != nil || n != 32 {
		t.Fatalf("chacha length = %d, %v", n, err)
	}
	if _, err := shadowsocks.KeyLength("unknown"); err == nil {
		t.Fatal("expected unsupported method error")
	}
}

func TestValidateKey_RejectsWrongLength(t *testing.T) {
	key, err := shadowsocks.GenerateKey("2022-blake3-aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	if err := shadowsocks.ValidateKey("2022-blake3-aes-256-gcm", key); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

func TestValidateKey_invalidBase64(t *testing.T) {
	err := shadowsocks.ValidateKey("2022-blake3-aes-128-gcm", "not!!!valid")
	if err == nil || !strings.Contains(err.Error(), "invalid base64 key") {
		t.Fatalf("expected base64 error, got %v", err)
	}
}

func TestValidateKey_unsupportedMethod(t *testing.T) {
	err := shadowsocks.ValidateKey("unknown", "8JCsPssfgS8tiRwiMlhARg==")
	if err == nil || !strings.Contains(err.Error(), "unsupported shadowsocks method") {
		t.Fatalf("expected method error, got %v", err)
	}
}
