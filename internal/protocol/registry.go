package protocol

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds registered protocol adapters keyed by protocol type name.
type Registry struct {
	mu        sync.RWMutex
	protocols map[string]Protocol
}

// NewRegistry returns an empty protocol registry.
func NewRegistry() *Registry {
	return &Registry{
		protocols: make(map[string]Protocol),
	}
}

// Register adds a protocol adapter to the registry.
// It panics if two adapters share the same Type value.
func (r *Registry) Register(p Protocol) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Type()
	if _, exists := r.protocols[name]; exists {
		panic(fmt.Sprintf("protocol %q already registered", name))
	}
	r.protocols[name] = p
}

// Get returns the adapter for the given protocol type.
func (r *Registry) Get(name string) (Protocol, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.protocols[name]
	if !ok {
		return nil, fmt.Errorf("unknown protocol %q", name)
	}
	return p, nil
}

// DisplayOrder is the preferred order for listing protocol types in UI and CLI.
var DisplayOrder = []string{"http", "socks5", "shadowsocks", "trojan", "wireguard", "vmess", "vless", "hysteria2", "tuic"}

// List returns all registered protocol type names in DisplayOrder, then any
// remaining types in lexicographic order.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	registered := make(map[string]struct{}, len(r.protocols))
	for name := range r.protocols {
		registered[name] = struct{}{}
	}
	names := make([]string, 0, len(registered))
	for _, name := range DisplayOrder {
		if _, ok := registered[name]; ok {
			names = append(names, name)
			delete(registered, name)
		}
	}
	extra := make([]string, 0, len(registered))
	for name := range registered {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	return append(names, extra...)
}
