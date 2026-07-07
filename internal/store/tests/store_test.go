package store_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ivan-khludov/obscura/internal/domain"
	"github.com/ivan-khludov/obscura/internal/store"
)

func openStore(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return s, context.Background()
}

func sampleVPN(name string) *domain.VPN {
	return &domain.VPN{
		Name:     name,
		Protocol: "socks5",
		Tag:      "vpn-" + name,
		Enabled:  true,
		Listen:   domain.DefaultListenOptions(),
	}
}

func seedVPN(t *testing.T, s *store.Store, ctx context.Context, vpn *domain.VPN) {
	t.Helper()
	if err := s.CreateVPN(ctx, vpn); err != nil {
		t.Fatal(err)
	}
}

func seedClient(t *testing.T, s *store.Store, ctx context.Context, client *domain.Client) {
	t.Helper()
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
}

func setupLegacyDBWithTables(t *testing.T) string {
	t.Helper()
	path := setupLegacyDB(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS clients (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	vpn_id INTEGER NOT NULL REFERENCES vpns(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	username TEXT NOT NULL,
	password TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(vpn_id, username),
	UNIQUE(vpn_id, name)
);
CREATE TABLE IF NOT EXISTS config_revisions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	singbox_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func setupLegacyDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE vpns (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	protocol TEXT NOT NULL,
	tag TEXT NOT NULL UNIQUE,
	enabled INTEGER NOT NULL DEFAULT 1,
	listen_json TEXT NOT NULL,
	protocol_json TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
INSERT INTO vpns (name, protocol, tag, enabled, listen_json, protocol_json, created_at, updated_at)
VALUES ('old', 'socks5', 'vpn-old', 1, '{"listen":"0.0.0.0","listen_port":1080}', '{}', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z');
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewFromDB_migrateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migrate-fail.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`SELECT 1`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = store.NewFromDB(db)
	if err == nil {
		t.Fatal("expected migration error")
	}
}

func TestOpen_ok(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	got, err := s.GetVPN(ctx, vpn.ID)
	if err != nil || got.Name != "main" {
		t.Fatalf("GetVPN: %#v err=%v", got, err)
	}
	if s.DB() == nil {
		t.Fatal("expected db handle")
	}
}

func TestOpen_openError(t *testing.T) {
	_, err := (&store.Opener{
		OpenDB: func(string, string) (*sql.DB, error) {
			return nil, errors.New("open failed")
		},
	}).Open(filepath.Join(t.TempDir(), "test.db"))
	if err == nil || !strings.Contains(err.Error(), "open database") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_foreignKeysError(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = (&store.Opener{
		OpenDB: func(string, string) (*sql.DB, error) { return db, nil },
	}).Open("ignored")
	if err == nil || !strings.Contains(err.Error(), "enable foreign keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_migrateError(t *testing.T) {
	s, _ := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.RunMigrations(); err == nil {
		t.Fatal("expected migration error on closed db")
	}
}

func TestNewFromDB_ok(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "fromdb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := store.NewFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if s.DB() != db {
		t.Fatal("expected same db handle")
	}
}

func TestNewFromDB_foreignKeysError(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = store.NewFromDB(db)
	if err == nil || !strings.Contains(err.Error(), "enable foreign keys") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_legacyDB(t *testing.T) {
	path := setupLegacyDB(t)
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	got, err := s.GetVPNByName(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientHost != "" {
		t.Fatalf("expected empty client_host after migration, got %q", got.ClientHost)
	}
	got.ClientHost = "migrated.example.com"
	if err := s.UpdateVPN(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetVPNByName(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientHost != "migrated.example.com" {
		t.Fatalf("client_host = %q", got.ClientHost)
	}
}

func TestMigrateClientHostColumn_queryError(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		QueryVpnsTableInfo: func(*sql.DB) (*sql.Rows, error) {
			return nil, errors.New("pragma failed")
		},
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "table info vpns") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_scanError(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		QueryVpnsTableInfo: func(db *sql.DB) (*sql.Rows, error) {
			return db.Query(`SELECT 1 AS cid, 'x' AS name`)
		},
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "scan table info") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_closeAfterScanError(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		QueryVpnsTableInfo: func(db *sql.DB) (*sql.Rows, error) {
			return db.Query(`SELECT 1 AS cid, 'x' AS name`)
		},
		CloseRows: func(*sql.Rows) error {
			return errors.New("close failed")
		},
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "close table info rows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_tableInfoRowsErr(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		QueryVpnsTableInfo: func(db *sql.DB) (*sql.Rows, error) {
			return db.Query(`PRAGMA table_info(vpns)`)
		},
		TableInfoRowsErr: func(*sql.Rows) error { return errors.New("rows failed") },
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "rows failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_closeAfterRowsErr(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		QueryVpnsTableInfo: func(db *sql.DB) (*sql.Rows, error) {
			return db.Query(`PRAGMA table_info(vpns)`)
		},
		TableInfoRowsErr: func(*sql.Rows) error { return errors.New("rows failed") },
		CloseRows:        func(*sql.Rows) error { return errors.New("close failed") },
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "close table info rows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_closeError(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		QueryVpnsTableInfo: func(db *sql.DB) (*sql.Rows, error) {
			return db.Query(`PRAGMA table_info(vpns)`)
		},
		CloseRows: func(*sql.Rows) error { return errors.New("close failed") },
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "close table info rows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_addColumnHookError(t *testing.T) {
	path := setupLegacyDB(t)
	_, err := (&store.Opener{
		AddClientHostColumn: func(*sql.DB) error {
			return errors.New("alter failed")
		},
	}).Open(path)
	if err == nil || !strings.Contains(err.Error(), "alter failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMigrateClientHostColumn_addColumnRealError(t *testing.T) {
	path := setupLegacyDBWithTables(t)
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
	_, err := store.Open(path)
	if err == nil || !strings.Contains(err.Error(), "add client_host column") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVPNClientHostRoundTrip(t *testing.T) {
	s, ctx := openStore(t)
	vpn := &domain.VPN{
		Name: "hy", Protocol: "hysteria2", Tag: "vpn-hy", Enabled: true,
		ClientHost: "culhackervpn.duckdns.org",
		Listen:     domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 20783},
	}
	seedVPN(t, s, ctx, vpn)
	got, err := s.GetVPNByName(ctx, "hy")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientHost != "culhackervpn.duckdns.org" {
		t.Fatalf("client_host = %q", got.ClientHost)
	}
	got.ClientHost = "vpn.example.com"
	if err := s.UpdateVPN(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetVPNByName(ctx, "hy")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientHost != "vpn.example.com" {
		t.Fatalf("updated client_host = %q", got.ClientHost)
	}
}

func TestVPNCRUD(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	vpn.ProtocolData = nil
	seedVPN(t, s, ctx, vpn)

	got, err := s.GetVPN(ctx, vpn.ID)
	if err != nil || got.Name != "main" {
		t.Fatalf("GetVPN: %#v err=%v", got, err)
	}

	disabled := sampleVPN("disabled")
	disabled.Enabled = false
	seedVPN(t, s, ctx, disabled)

	all, err := s.ListVPNs(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListVPNs: len=%d err=%v", len(all), err)
	}
	enabled, err := s.ListEnabledVPNs(ctx)
	if err != nil || len(enabled) != 1 || enabled[0].Name != "main" {
		t.Fatalf("ListEnabledVPNs: %#v err=%v", enabled, err)
	}

	got.Enabled = false
	if err := s.UpdateVPN(ctx, got); err != nil {
		t.Fatal(err)
	}
	enabled, err = s.ListEnabledVPNs(ctx)
	if err != nil || len(enabled) != 0 {
		t.Fatalf("ListEnabledVPNs after disable: %#v err=%v", enabled, err)
	}

	if err := s.DeleteVPN(ctx, 999); err == nil || !strings.Contains(err.Error(), "vpn not found") {
		t.Fatalf("DeleteVPN missing: %v", err)
	}
	if err := s.DeleteVPN(ctx, vpn.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCreateVPN_errors(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("dup")
	seedVPN(t, s, ctx, vpn)

	dup := sampleVPN("dup")
	if err := s.CreateVPN(ctx, dup); err == nil || !strings.Contains(err.Error(), "insert vpn") {
		t.Fatalf("duplicate insert: %v", err)
	}

	s.MarshalListen = func(domain.ListenOptions) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	if err := s.CreateVPN(ctx, sampleVPN("other")); err == nil || !strings.Contains(err.Error(), "marshal listen") {
		t.Fatalf("marshal error: %v", err)
	}

	s.MarshalListen = nil
	s.LastInsertID = func(sql.Result) (int64, error) {
		return 0, errors.New("last insert failed")
	}
	if err := s.CreateVPN(ctx, sampleVPN("third")); err == nil || !strings.Contains(err.Error(), "last insert id") {
		t.Fatalf("last insert error: %v", err)
	}
}

func TestUpdateVPN_errors(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	s.MarshalListen = func(domain.ListenOptions) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	if err := s.UpdateVPN(ctx, vpn); err == nil || !strings.Contains(err.Error(), "marshal listen") {
		t.Fatalf("marshal error: %v", err)
	}
}

func TestDeleteVPN_rowsAffectedError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	s.RowsAffected = func(sql.Result) (int64, error) {
		return 0, errors.New("rows affected failed")
	}
	if err := s.DeleteVPN(ctx, vpn.ID); err == nil || !strings.Contains(err.Error(), "delete vpn rows") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetVPN_notFound(t *testing.T) {
	s, ctx := openStore(t)
	_, err := s.GetVPN(ctx, 404)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestGetVPN_badListenJSON(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("bad")
	seedVPN(t, s, ctx, vpn)
	if _, err := s.DB().Exec(`UPDATE vpns SET listen_json='not-json' WHERE id=?`, vpn.ID); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetVPN(ctx, vpn.ID)
	if err == nil || !strings.Contains(err.Error(), "unmarshal listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListVPNs_errors(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListVPNs(ctx); err == nil || !strings.Contains(err.Error(), "list vpns") {
		t.Fatalf("unexpected error: %v", err)
	}

	s, ctx = openStore(t)
	vpn := sampleVPN("bad-list")
	seedVPN(t, s, ctx, vpn)
	if _, err := s.DB().Exec(`UPDATE vpns SET listen_json='bad' WHERE id=?`, vpn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListVPNs(ctx); err == nil || !strings.Contains(err.Error(), "unmarshal listen") {
		t.Fatalf("unexpected error: %v", err)
	}

	s, ctx = openStore(t)
	seedVPN(t, s, ctx, sampleVPN("close-rows"))
	s.CloseRows = func(*sql.Rows) error { return errors.New("close failed") }
	var listErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic: %v", r)
			}
		}()
		_, listErr = s.ListVPNs(ctx)
	}()
	if listErr == nil || !strings.Contains(listErr.Error(), "close failed") {
		t.Fatalf("unexpected error: %v", listErr)
	}
}

func TestClientCRUD(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)

	client := &domain.Client{
		VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true,
	}
	seedClient(t, s, ctx, client)

	got, err := s.GetClient(ctx, client.ID)
	if err != nil || got.Name != "phone" {
		t.Fatalf("GetClient: %#v err=%v", got, err)
	}
	byName, err := s.GetClientByName(ctx, vpn.ID, "phone")
	if err != nil || byName.ID != client.ID {
		t.Fatalf("GetClientByName: %#v err=%v", byName, err)
	}

	client.Enabled = false
	if err := s.UpdateClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	disabled := &domain.Client{
		VPNID: vpn.ID, Name: "tablet", Username: "tablet", Password: "secret", Enabled: false,
	}
	seedClient(t, s, ctx, disabled)

	all, err := s.ListClientsByVPN(ctx, vpn.ID)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListClientsByVPN: len=%d err=%v", len(all), err)
	}
	enabled, err := s.ListEnabledClientsByVPN(ctx, vpn.ID)
	if err != nil || len(enabled) != 0 {
		t.Fatalf("ListEnabledClientsByVPN: %#v err=%v", enabled, err)
	}

	if err := s.DeleteClient(ctx, client.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCreateClient_errors(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	client := &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true}
	seedClient(t, s, ctx, client)

	dup := &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "other", Password: "secret", Enabled: true}
	if err := s.CreateClient(ctx, dup); err == nil || !strings.Contains(err.Error(), "insert client") {
		t.Fatalf("duplicate insert: %v", err)
	}

	s.LastInsertID = func(sql.Result) (int64, error) {
		return 0, errors.New("last insert failed")
	}
	if err := s.CreateClient(ctx, &domain.Client{VPNID: vpn.ID, Name: "x", Username: "x", Password: "secret"}); err == nil || !strings.Contains(err.Error(), "last insert id") {
		t.Fatalf("last insert error: %v", err)
	}
}

func TestUpdateClient_error(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	client := &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true}
	seedClient(t, s, ctx, client)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateClient(ctx, client); err == nil || !strings.Contains(err.Error(), "update client") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteClient_error(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClient(ctx, 1); err == nil || !strings.Contains(err.Error(), "delete client") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListClientsByVPN_error(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListClientsByVPN(ctx, 1); err == nil || !strings.Contains(err.Error(), "list clients") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListEnabledClientsByVPN_error(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListEnabledClientsByVPN(ctx, 1); err == nil || !strings.Contains(err.Error(), "list enabled clients") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSaveRevisionAndPrevious(t *testing.T) {
	s, ctx := openStore(t)
	first := []byte(`{"version":1}`)
	second := []byte(`{"version":2}`)
	if _, err := s.SaveRevision(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRevision(ctx, second); err != nil {
		t.Fatal(err)
	}
	latest, _, err := s.LatestRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(latest) != string(second) {
		t.Fatalf("latest mismatch: %q", latest)
	}
	prev, _, err := s.PreviousRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(prev) != string(first) {
		t.Fatalf("previous mismatch: %q", prev)
	}
}

func TestLatestRevision_noRows(t *testing.T) {
	s, ctx := openStore(t)
	_, _, err := s.LatestRevision(ctx)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestPreviousRevision_noRows(t *testing.T) {
	s, ctx := openStore(t)
	if _, err := s.SaveRevision(ctx, []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.PreviousRevision(ctx)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestSaveRevision_errors(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRevision(ctx, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "save revision") {
		t.Fatalf("unexpected error: %v", err)
	}

	s, ctx = openStore(t)
	s.LastInsertID = func(sql.Result) (int64, error) {
		return 0, errors.New("last insert failed")
	}
	if _, err := s.SaveRevision(ctx, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "last insert") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteVPN_deletesClients(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	seedClient(t, s, ctx, &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true})
	if err := s.DeleteVPN(ctx, vpn.ID); err != nil {
		t.Fatal(err)
	}
	clients, err := s.ListClientsByVPN(ctx, vpn.ID)
	if err != nil || len(clients) != 0 {
		t.Fatalf("expected 0 clients, got %d err=%v", len(clients), err)
	}
}

func TestUpdateVPN_readError(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	vpn := sampleVPN("main")
	if err := s.UpdateVPN(ctx, vpn); err == nil || !strings.Contains(err.Error(), "update vpn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListEnabledVPNs_error(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListEnabledVPNs(ctx); err == nil || !strings.Contains(err.Error(), "list enabled vpns") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetClient_notFound(t *testing.T) {
	s, ctx := openStore(t)
	_, err := s.GetClient(ctx, 404)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestGetClientByName_notFound(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	_, err := s.GetClientByName(ctx, vpn.ID, "missing")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestGetVPNByName_notFound(t *testing.T) {
	s, ctx := openStore(t)
	_, err := s.GetVPNByName(ctx, "missing")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestCreateVPN_readError(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateVPN(ctx, sampleVPN("main")); err == nil || !strings.Contains(err.Error(), "insert vpn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateVPN_customListenPort(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	vpn.Listen = domain.ListenOptions{Listen: "0.0.0.0", ListenPort: 2222}
	seedVPN(t, s, ctx, vpn)
	got, err := s.GetVPNByName(ctx, "main")
	if err != nil || got.Listen.ListenPort != 2222 {
		t.Fatalf("got %#v err=%v", got.Listen, err)
	}
}

func TestDeleteVPN_deleteClientsError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteVPN(ctx, vpn.ID); err == nil || !strings.Contains(err.Error(), "delete clients") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListEnabledVPNs_scanError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("bad-enabled")
	seedVPN(t, s, ctx, vpn)
	if _, err := s.DB().Exec(`UPDATE vpns SET listen_json='bad' WHERE id=?`, vpn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListEnabledVPNs(ctx); err == nil || !strings.Contains(err.Error(), "unmarshal listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteVPN_deleteVPNError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	if _, err := s.DB().Exec(`DELETE FROM vpns WHERE id=?`, vpn.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteVPN(ctx, vpn.ID); err == nil || !strings.Contains(err.Error(), "vpn not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListClientsByVPN_closeRowsError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	seedClient(t, s, ctx, &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true})
	s.CloseRows = func(*sql.Rows) error { return errors.New("close failed") }
	_, err := s.ListClientsByVPN(ctx, vpn.ID)
	if err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListClientsByVPN_scanError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	client := &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true}
	seedClient(t, s, ctx, client)
	if _, err := s.DB().Exec(`UPDATE clients SET enabled='bad' WHERE id=?`, client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListClientsByVPN(ctx, vpn.ID); err == nil {
		t.Fatal("expected scan error")
	}
}

func TestListEnabledClientsByVPN_okAndError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	seedClient(t, s, ctx, &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true})
	enabled, err := s.ListEnabledClientsByVPN(ctx, vpn.ID)
	if err != nil || len(enabled) != 1 {
		t.Fatalf("ListEnabledClientsByVPN: %#v err=%v", enabled, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListEnabledClientsByVPN(ctx, vpn.ID); err == nil || !strings.Contains(err.Error(), "list enabled clients") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteVPN_deleteVPNExecError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	s.DeleteVPNRecord = func(context.Context, int64) (sql.Result, error) {
		return nil, errors.New("delete vpn failed")
	}
	if err := s.DeleteVPN(ctx, vpn.ID); err == nil || !strings.Contains(err.Error(), "delete vpn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListEnabledClientsByVPN_closeRowsError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	seedClient(t, s, ctx, &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true})
	s.CloseRows = func(*sql.Rows) error { return errors.New("close failed") }
	_, err := s.ListEnabledClientsByVPN(ctx, vpn.ID)
	if err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListEnabledClientsByVPN_scanError(t *testing.T) {
	s, ctx := openStore(t)
	vpn := sampleVPN("main")
	seedVPN(t, s, ctx, vpn)
	seedClient(t, s, ctx, &domain.Client{VPNID: vpn.ID, Name: "phone", Username: "phone", Password: "secret", Enabled: true})
	s.ScanClientRow = func(*sql.Rows) (*domain.Client, error) {
		return nil, errors.New("scan failed")
	}
	if _, err := s.ListEnabledClientsByVPN(ctx, vpn.ID); err == nil || !strings.Contains(err.Error(), "scan failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLatestRevision_closedDB(t *testing.T) {
	s, ctx := openStore(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.LatestRevision(ctx)
	if err == nil {
		t.Fatal("expected error on closed db")
	}
}

func TestMigrate_hasClientHostColumn(t *testing.T) {
	s, _ := openStore(t)
	if err := s.RunMigrations(); err != nil {
		t.Fatal(err)
	}
}
