package service_test

import (
	"testing"

	"github.com/ivan-khludov/obscura/internal/service"
)

func TestBuildProtocolDataPreview(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.BuildProtocolDataPreviewForTest(service.CreateVPNInput{
		Name: "vl", Protocol: "vless",
		VLESS: service.VLESSCreateOptions{ServerName: "example.com"},
	}, "vpn-vl")
	if err != nil {
		t.Fatal(err)
	}
}
