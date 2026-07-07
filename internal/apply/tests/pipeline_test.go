package apply_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/apply"
	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/render"
	"github.com/ivan-khludov/obscura/internal/runtime"
	"github.com/ivan-khludov/obscura/internal/store"
)

type renderFunc func(context.Context) ([]byte, error)

func (f renderFunc) Render(ctx context.Context) ([]byte, error) {
	return f(ctx)
}

type fakeChecker struct {
	err error
}

func (f fakeChecker) Check(_ context.Context, _ string) error {
	return f.err
}

type reloadRecorder struct {
	calls int
	err   error
}

func (r *reloadRecorder) Reload(_ context.Context) error {
	r.calls++
	return r.err
}

func (r *reloadRecorder) IsActive(_ context.Context) (bool, error) {
	return false, nil
}

type testRenderer interface {
	Render(context.Context) ([]byte, error)
}

func openTestStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return st
}

func newTestPipeline(t *testing.T, renderer testRenderer, checker apply.SingBoxChecker, reloader apply.ServiceManager, opts apply.Options) (*apply.Pipeline, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = filepath.Join(dir, "sing-box.json")
	}
	st := openTestStore(t, dir)
	if renderer == nil {
		renderer = render.NewRenderer(st, runtime.NewProtocolRegistry())
	}
	p := apply.NewPipeline(renderer, st, checker, reloader, apply.Options{ConfigPath: cfgPath})
	return p, st, cfgPath
}

func seedVPNWithClient(t *testing.T, st *store.Store) {
	seedNamedVPNWithClient(t, st, "main", "vpn-main", 1080)
}

func seedNamedVPNWithClient(t *testing.T, st *store.Store, name, tag string, port int) {
	t.Helper()
	ctx := context.Background()
	vpn := &domain.VPN{
		Name: name, Protocol: "socks5", Tag: tag, Enabled: true,
		Listen: domain.ListenOptions{Listen: "0.0.0.0", ListenPort: port},
	}
	if err := st.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone-" + name, Username: "phone-" + name, Password: "secret", Enabled: true,
	}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
}

func validJSONRenderer(t *testing.T, st *store.Store) testRenderer {
	t.Helper()
	return render.NewRenderer(st, runtime.NewProtocolRegistry())
}

func applyTwoRevisions(t *testing.T, p *apply.Pipeline, st *store.Store, ctx context.Context) {
	t.Helper()
	seedVPNWithClient(t, st)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	seedNamedVPNWithClient(t, st, "second", "vpn-second", 1081)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
}

func TestNewPipeline_DefaultConfigPath(t *testing.T) {
	dir := t.TempDir()
	st := openTestStore(t, dir)
	p := apply.NewPipeline(renderFunc(func(context.Context) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	}), st, nil, nil, apply.Options{})
	if p.ConfigPathForTest() != render.DefaultConfigPath {
		t.Fatalf("config path: got %q want %q", p.ConfigPathForTest(), render.DefaultConfigPath)
	}
}

func TestApply_DryRun(t *testing.T) {
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, &reloadRecorder{}, apply.Options{})
	seedVPNWithClient(t, st)
	ctx := context.Background()

	result, err := p.Apply(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun != true || len(result.Bytes) == 0 {
		t.Fatalf("unexpected dry-run result: %#v", result)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("expected config file absent after dry-run")
	}
}

func TestApply_CheckFailure(t *testing.T) {
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{err: errors.New("invalid config")}, &reloadRecorder{}, apply.Options{})
	seedVPNWithClient(t, st)
	ctx := context.Background()

	if err := os.WriteFile(cfgPath, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := p.Apply(ctx, false)
	if err == nil {
		t.Fatal("expected apply error")
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"old":true}` {
		t.Fatalf("config mutated on check failure: %q", data)
	}
	if _, err := os.Stat(cfgPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("expected temp file removed")
	}
}

func TestApply_Success(t *testing.T) {
	reloader := &reloadRecorder{}
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	seedVPNWithClient(t, st)
	ctx := context.Background()

	result, err := p.Apply(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun || len(result.Bytes) == 0 {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if reloader.calls != 1 {
		t.Fatalf("expected 1 reload, got %d", reloader.calls)
	}
	if _, _, err := st.LatestRevision(ctx); err != nil {
		t.Fatalf("expected revision saved: %v", err)
	}
}

func TestApply_SkipsReloadWhenUnchanged(t *testing.T) {
	reloader := &reloadRecorder{}
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	seedVPNWithClient(t, st)
	ctx := context.Background()

	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	if reloader.calls != 1 {
		t.Fatalf("expected 1 reload after first apply, got %d", reloader.calls)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	firstModTime := info.ModTime()

	// Applying again with an identical config must not restart sing-box.
	result, err := p.Apply(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun || len(result.Bytes) == 0 {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	if reloader.calls != 1 {
		t.Fatalf("expected no extra reload for unchanged config, got %d", reloader.calls)
	}
	info, err = os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(firstModTime) {
		t.Fatal("expected config file untouched when unchanged")
	}
	if _, err := os.Stat(cfgPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected temp config removed, got err=%v", err)
	}
}

func TestApply_RenderError(t *testing.T) {
	dir := t.TempDir()
	st := openTestStore(t, dir)
	cfgPath := filepath.Join(dir, "sing-box.json")
	p := apply.NewPipeline(renderFunc(func(context.Context) ([]byte, error) {
		return nil, errors.New("render failed")
	}), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	_, err := p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "render:") {
		t.Fatalf("expected render error, got %v", err)
	}
}

func TestApply_EmptyConfig(t *testing.T) {
	dir := t.TempDir()
	st := openTestStore(t, dir)
	cfgPath := filepath.Join(dir, "sing-box.json")
	p := apply.NewPipeline(renderFunc(func(context.Context) ([]byte, error) {
		return []byte("not-json"), nil
	}), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	_, err := p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "render produced empty config") {
		t.Fatalf("expected empty config error, got %v", err)
	}
}

func TestApply_MkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(blocker, "nested", "sing-box.json")
	st := openTestStore(t, dir)
	p := apply.NewPipeline(renderFunc(func(context.Context) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	}), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	_, err := p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "mkdir config dir:") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}

func TestApply_WriteTempError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sing-box.json")
	if err := os.Mkdir(cfgPath+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	st := openTestStore(t, dir)
	p := apply.NewPipeline(renderFunc(func(context.Context) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	}), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	_, err := p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "write temp config:") {
		t.Fatalf("expected write temp error, got %v", err)
	}
}

func TestApply_NilChecker(t *testing.T) {
	p, st, cfgPath := newTestPipeline(t, nil, nil, &reloadRecorder{}, apply.Options{})
	seedVPNWithClient(t, st)

	result, err := p.Apply(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun || len(result.Bytes) == 0 {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not written: %v", err)
	}
}

func TestApply_CommitError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sing-box.json")
	if err := os.Mkdir(cfgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	st := openTestStore(t, dir)
	seedVPNWithClient(t, st)
	p := apply.NewPipeline(validJSONRenderer(t, st), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	_, err := p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "commit config:") {
		t.Fatalf("expected commit error, got %v", err)
	}
}

func TestApply_SaveRevisionError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sing-box.json")
	dbPath := filepath.Join(dir, "state.db")
	st := openTestStore(t, dir)
	seedVPNWithClient(t, st)

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dbPath, 0o644)
	})

	stRO, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stRO.Close()
	})
	p := apply.NewPipeline(validJSONRenderer(t, stRO), stRO, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	_, err = p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "save revision:") {
		t.Fatalf("expected save revision error, got %v", err)
	}
}

func TestApply_NilSystemd(t *testing.T) {
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, nil, apply.Options{})
	seedVPNWithClient(t, st)

	result, err := p.Apply(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.DryRun || len(result.Bytes) == 0 {
		t.Fatalf("unexpected apply result: %#v", result)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not written: %v", err)
	}
}

func TestApply_ReloadError(t *testing.T) {
	reloader := &reloadRecorder{err: errors.New("reload failed")}
	p, st, _ := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	seedVPNWithClient(t, st)

	_, err := p.Apply(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "reload sing-box:") {
		t.Fatalf("expected reload error, got %v", err)
	}
}

func TestRollback_RestoresPrevious(t *testing.T) {
	reloader := &reloadRecorder{}
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	ctx := context.Background()

	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	seedNamedVPNWithClient(t, st, "second", "vpn-second", 1081)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(second) {
		t.Fatal("expected distinct config revisions")
	}

	if err := p.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(first) {
		t.Fatalf("rollback config mismatch:\nfirst=%q\nrestored=%q", first, restored)
	}
	if reloader.calls != 3 {
		t.Fatalf("expected 3 reloads (2 apply + 1 rollback), got %d", reloader.calls)
	}
}

func TestRollback_NoPreviousRevision(t *testing.T) {
	p, _, _ := newTestPipeline(t, nil, fakeChecker{}, &reloadRecorder{}, apply.Options{})

	err := p.Rollback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "previous revision:") {
		t.Fatalf("expected previous revision error, got %v", err)
	}
}

func TestRollback_WriteTempError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sing-box.json")
	st := openTestStore(t, dir)
	if _, err := st.SaveRevision(context.Background(), []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRevision(context.Background(), []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfgPath+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	p := apply.NewPipeline(renderFunc(func(context.Context) ([]byte, error) {
		return []byte(`{"v":2}`), nil
	}), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	err := p.Rollback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write rollback temp:") {
		t.Fatalf("expected write rollback temp error, got %v", err)
	}
}

func TestRollback_CheckFailure(t *testing.T) {
	reloader := &reloadRecorder{}
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	ctx := context.Background()
	applyTwoRevisions(t, p, st, ctx)

	p = apply.NewPipeline(validJSONRenderer(t, st), st, fakeChecker{err: errors.New("bad rollback config")}, reloader, apply.Options{ConfigPath: cfgPath})
	if err := p.Rollback(ctx); err == nil || !strings.Contains(err.Error(), "sing-box check rollback:") {
		t.Fatalf("expected rollback check error, got %v", err)
	}
	if _, err := os.Stat(cfgPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("expected temp file removed after rollback check failure")
	}
}

func TestRollback_NilChecker(t *testing.T) {
	reloader := &reloadRecorder{}
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	ctx := context.Background()
	seedVPNWithClient(t, st)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	seedNamedVPNWithClient(t, st, "second", "vpn-second", 1081)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}

	p = apply.NewPipeline(validJSONRenderer(t, st), st, nil, reloader, apply.Options{ConfigPath: cfgPath})
	if err := p.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(first) {
		t.Fatalf("rollback config mismatch: got %q want %q", restored, first)
	}
}

func TestRollback_CommitError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sing-box.json")
	st := openTestStore(t, dir)
	ctx := context.Background()
	p := apply.NewPipeline(validJSONRenderer(t, st), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})
	applyTwoRevisions(t, p, st, ctx)

	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfgPath, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := p.Rollback(ctx); err == nil || !strings.Contains(err.Error(), "commit rollback:") {
		t.Fatalf("expected commit rollback error, got %v", err)
	}
}

func TestRollback_SaveRevisionError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sing-box.json")
	dbPath := filepath.Join(dir, "state.db")
	st := openTestStore(t, dir)
	ctx := context.Background()
	p := apply.NewPipeline(validJSONRenderer(t, st), st, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})
	applyTwoRevisions(t, p, st, ctx)

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dbPath, 0o644)
	})

	stRO, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stRO.Close()
	})
	p = apply.NewPipeline(validJSONRenderer(t, stRO), stRO, fakeChecker{}, &reloadRecorder{}, apply.Options{ConfigPath: cfgPath})

	if err := p.Rollback(ctx); err == nil || !strings.Contains(err.Error(), "save rollback revision:") {
		t.Fatalf("expected save rollback revision error, got %v", err)
	}
}

func TestRollback_NilSystemd(t *testing.T) {
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, &reloadRecorder{}, apply.Options{})
	ctx := context.Background()
	seedVPNWithClient(t, st)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	seedNamedVPNWithClient(t, st, "second", "vpn-second", 1081)
	if _, err := p.Apply(ctx, false); err != nil {
		t.Fatal(err)
	}

	p = apply.NewPipeline(validJSONRenderer(t, st), st, fakeChecker{}, nil, apply.Options{ConfigPath: cfgPath})
	if err := p.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(first) {
		t.Fatalf("rollback config mismatch: got %q want %q", restored, first)
	}
}

func TestRollback_ReloadError(t *testing.T) {
	reloader := &reloadRecorder{}
	p, st, cfgPath := newTestPipeline(t, nil, fakeChecker{}, reloader, apply.Options{})
	ctx := context.Background()
	applyTwoRevisions(t, p, st, ctx)

	reloader.err = errors.New("reload failed")
	p = apply.NewPipeline(validJSONRenderer(t, st), st, fakeChecker{}, reloader, apply.Options{ConfigPath: cfgPath})
	if err := p.Rollback(ctx); err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("expected reload error, got %v", err)
	}
}
