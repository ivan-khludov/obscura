package render_test

import (
	"encoding/json"
	"testing"

	"github.com/ivan-khludov/obscura/internal/render"
)

func TestConfig_JSON(t *testing.T) {
	t.Run("without endpoints", func(t *testing.T) {
		cfg := render.Config{
			Log:       render.LogConfig{Level: "info"},
			Inbounds:  []map[string]any{{"type": "socks"}},
			Outbounds: []render.Outbound{{Type: "direct", Tag: "direct"}},
			Route:     render.RouteConfig{Final: "direct"},
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) == "" || string(raw)[0] != '{' {
			t.Fatalf("unexpected json: %s", raw)
		}
		var decoded render.Config
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Log.Level != "info" || decoded.Route.Final != "direct" {
			t.Fatalf("unexpected decoded config: %#v", decoded)
		}
		if len(decoded.Endpoints) != 0 {
			t.Fatalf("expected no endpoints, got %#v", decoded.Endpoints)
		}
	})

	t.Run("with endpoints omitempty", func(t *testing.T) {
		cfg := render.Config{
			Log:       render.LogConfig{Level: "debug"},
			Inbounds:  nil,
			Outbounds: []render.Outbound{{Type: "direct", Tag: "direct"}},
			Route:     render.RouteConfig{Final: "direct", Rules: []map[string]any{{"outbound": "direct"}}},
			Endpoints: []map[string]any{{"type": "wireguard", "tag": "wg"}},
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(raw) {
			t.Fatal("expected valid json")
		}
		var decoded render.Config
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Endpoints) != 1 || decoded.Endpoints[0]["type"] != "wireguard" {
			t.Fatalf("unexpected endpoints: %#v", decoded.Endpoints)
		}
		if len(decoded.Route.Rules) != 1 {
			t.Fatalf("unexpected rules: %#v", decoded.Route.Rules)
		}
	})
}

func TestDefaultConfigPath(t *testing.T) {
	if render.DefaultConfigPath == "" {
		t.Fatal("expected non-empty default config path")
	}
}
