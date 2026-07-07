package protocol_test

import (
	"errors"
	"testing"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/protocol"
)

func TestClientQRFromURI(t *testing.T) {
	stub := stubProtocol{typ: "test", uri: "uri://example"}
	got, err := protocol.ClientQRFromURI(stub, domain.VPNConfig{}, nil, domain.ClientConfig{}, "host")
	if err != nil || got != "uri://example" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestClientQRFromURI_error(t *testing.T) {
	stub := stubProtocol{typ: "test", uriErr: errors.New("uri failed")}
	_, err := protocol.ClientQRFromURI(stub, domain.VPNConfig{}, nil, domain.ClientConfig{}, "host")
	if err == nil {
		t.Fatal("expected error")
	}
}
