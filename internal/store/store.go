// Package store provides SQLite persistence for VPNs, clients, and config revisions.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ivan-khludov/obscura/internal/domain"
)

// Opener opens SQLite stores with optional dependency injection for tests.
type Opener struct {
	OpenDB              func(driverName, dataSourceName string) (*sql.DB, error)
	QueryVpnsTableInfo  func(db *sql.DB) (*sql.Rows, error)
	AddClientHostColumn func(db *sql.DB) error
	CloseRows           func(*sql.Rows) error
	TableInfoRowsErr    func(*sql.Rows) error
}

// Store wraps SQLite access for obscura domain entities.
type Store struct {
	db *sql.DB

	QueryVpnsTableInfo  func() (*sql.Rows, error)
	AddClientHostColumn func() error
	TableInfoRowsErr    func(*sql.Rows) error
	DeleteVPNRecord     func(ctx context.Context, id int64) (sql.Result, error)
	ScanClientRow       func(rows *sql.Rows) (*domain.Client, error)
	MarshalListen       func(domain.ListenOptions) ([]byte, error)
	CloseRows           func(*sql.Rows) error
	LastInsertID        func(sql.Result) (int64, error)
	RowsAffected        func(sql.Result) (int64, error)
}

// Open opens or creates a SQLite database at path and runs migrations.
func Open(path string) (*Store, error) {
	return (&Opener{}).Open(path)
}

// Open opens or creates a SQLite database at path and runs migrations.
func (o *Opener) Open(path string) (*Store, error) {
	openFn := sql.Open
	if o != nil && o.OpenDB != nil {
		openFn = o.OpenDB
	}
	db, err := openFn("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	s := &Store{db: db}
	if o != nil {
		if o.QueryVpnsTableInfo != nil {
			s.QueryVpnsTableInfo = func() (*sql.Rows, error) {
				return o.QueryVpnsTableInfo(db)
			}
		}
		if o.AddClientHostColumn != nil {
			s.AddClientHostColumn = func() error {
				return o.AddClientHostColumn(db)
			}
		}
		if o.CloseRows != nil {
			s.CloseRows = o.CloseRows
		}
		if o.TableInfoRowsErr != nil {
			s.TableInfoRowsErr = o.TableInfoRowsErr
		}
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewFromDB initializes a store from an existing database connection.
func NewFromDB(db *sql.DB) (*Store, error) {
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying database handle for tests.
func (s *Store) DB() *sql.DB {
	return s.db
}

// RunMigrations applies schema migrations to the database.
func (s *Store) RunMigrations() error {
	return s.migrate()
}

// migrate creates database tables when they do not exist.
func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS vpns (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	protocol TEXT NOT NULL,
	tag TEXT NOT NULL UNIQUE,
	enabled INTEGER NOT NULL DEFAULT 1,
	client_host TEXT NOT NULL DEFAULT '',
	listen_json TEXT NOT NULL,
	protocol_json TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
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
		return err
	}
	return s.migrateClientHostColumn()
}

func (s *Store) migrateClientHostColumn() error {
	query := func() (*sql.Rows, error) {
		if s.QueryVpnsTableInfo != nil {
			return s.QueryVpnsTableInfo()
		}
		return s.db.Query(`PRAGMA table_info(vpns)`)
	}
	rows, err := query()
	if err != nil {
		return fmt.Errorf("table info vpns: %w", err)
	}
	hasColumn := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			if closeErr := s.closeTableInfoRows(rows); closeErr != nil {
				return fmt.Errorf("close table info rows: %w", closeErr)
			}
			return fmt.Errorf("scan table info: %w", err)
		}
		if name == "client_host" {
			hasColumn = true
			break
		}
	}
	if err := s.tableInfoRowsErr(rows); err != nil {
		if closeErr := s.closeTableInfoRows(rows); closeErr != nil {
			return fmt.Errorf("close table info rows: %w", closeErr)
		}
		return err
	}
	if err := s.closeTableInfoRows(rows); err != nil {
		return fmt.Errorf("close table info rows: %w", err)
	}
	if hasColumn {
		return nil
	}
	if s.AddClientHostColumn != nil {
		return s.AddClientHostColumn()
	}
	if _, err := s.db.Exec(`ALTER TABLE vpns ADD COLUMN client_host TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add client_host column: %w", err)
	}
	return nil
}

// CreateVPN inserts a new VPN record.
func (s *Store) CreateVPN(ctx context.Context, vpn *domain.VPN) error {
	marshalListen := func(lo domain.ListenOptions) ([]byte, error) {
		return json.Marshal(lo)
	}
	if s.MarshalListen != nil {
		marshalListen = s.MarshalListen
	}
	listenJSON, err := marshalListen(vpn.Listen)
	if err != nil {
		return fmt.Errorf("marshal listen: %w", err)
	}
	now := time.Now().UTC()
	vpn.CreatedAt = now
	vpn.UpdatedAt = now
	if vpn.ProtocolData == nil {
		vpn.ProtocolData = []byte("{}")
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO vpns (name, protocol, tag, enabled, client_host, listen_json, protocol_json, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vpn.Name, vpn.Protocol, vpn.Tag, boolToInt(vpn.Enabled), vpn.ClientHost, string(listenJSON), string(vpn.ProtocolData), formatTime(now), formatTime(now))
	if err != nil {
		return fmt.Errorf("insert vpn: %w", err)
	}
	id, err := s.lastInsertID(result)
	if err != nil {
		return fmt.Errorf("last insert id: %w", err)
	}
	vpn.ID = id
	return nil
}

// UpdateVPN updates an existing VPN record.
func (s *Store) UpdateVPN(ctx context.Context, vpn *domain.VPN) error {
	marshalListen := func(lo domain.ListenOptions) ([]byte, error) {
		return json.Marshal(lo)
	}
	if s.MarshalListen != nil {
		marshalListen = s.MarshalListen
	}
	listenJSON, err := marshalListen(vpn.Listen)
	if err != nil {
		return fmt.Errorf("marshal listen: %w", err)
	}
	vpn.UpdatedAt = time.Now().UTC()
	if vpn.ProtocolData == nil {
		vpn.ProtocolData = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE vpns SET name=?, protocol=?, tag=?, enabled=?, client_host=?, listen_json=?, protocol_json=?, updated_at=?
WHERE id=?`,
		vpn.Name, vpn.Protocol, vpn.Tag, boolToInt(vpn.Enabled), vpn.ClientHost, string(listenJSON), string(vpn.ProtocolData), formatTime(vpn.UpdatedAt), vpn.ID)
	if err != nil {
		return fmt.Errorf("update vpn: %w", err)
	}
	return nil
}

// DeleteVPN removes a VPN and its clients.
func (s *Store) DeleteVPN(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE vpn_id=?`, id); err != nil {
		return fmt.Errorf("delete clients: %w", err)
	}
	res, err := s.deleteVPNRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("delete vpn: %w", err)
	}
	n, err := s.rowsAffected(res)
	if err != nil {
		return fmt.Errorf("delete vpn rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("vpn not found")
	}
	return nil
}

// GetVPN returns a VPN by ID.
func (s *Store) GetVPN(ctx context.Context, id int64) (*domain.VPN, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, protocol, tag, enabled, client_host, listen_json, protocol_json, created_at, updated_at
FROM vpns WHERE id=?`, id)
	return scanVPN(row)
}

// GetVPNByName returns a VPN by unique name.
func (s *Store) GetVPNByName(ctx context.Context, name string) (*domain.VPN, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, protocol, tag, enabled, client_host, listen_json, protocol_json, created_at, updated_at
FROM vpns WHERE name=?`, name)
	return scanVPN(row)
}

// ListVPNs returns all VPN records.
func (s *Store) ListVPNs(ctx context.Context) (_ []domain.VPN, err error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, protocol, tag, enabled, client_host, listen_json, protocol_json, created_at, updated_at
FROM vpns ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list vpns: %w", err)
	}
	defer s.closeRowsOnReturn(rows, &err)
	var vpns []domain.VPN
	for rows.Next() {
		vpn, err := scanVPNRow(rows)
		if err != nil {
			return nil, err
		}
		vpns = append(vpns, *vpn)
	}
	return vpns, rows.Err()
}

// ListEnabledVPNs returns only enabled VPN records.
func (s *Store) ListEnabledVPNs(ctx context.Context) (_ []domain.VPN, err error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, protocol, tag, enabled, client_host, listen_json, protocol_json, created_at, updated_at
FROM vpns WHERE enabled=1 ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list enabled vpns: %w", err)
	}
	defer s.closeRowsOnReturn(rows, &err)
	var vpns []domain.VPN
	for rows.Next() {
		vpn, err := scanVPNRow(rows)
		if err != nil {
			return nil, err
		}
		vpns = append(vpns, *vpn)
	}
	return vpns, rows.Err()
}

// CreateClient inserts a new client record.
func (s *Store) CreateClient(ctx context.Context, client *domain.Client) error {
	now := time.Now().UTC()
	client.CreatedAt = now
	client.UpdatedAt = now
	result, err := s.db.ExecContext(ctx, `
INSERT INTO clients (vpn_id, name, username, password, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		client.VPNID, client.Name, client.Username, client.Password, boolToInt(client.Enabled), formatTime(now), formatTime(now))
	if err != nil {
		return fmt.Errorf("insert client: %w", err)
	}
	id, err := s.lastInsertID(result)
	if err != nil {
		return fmt.Errorf("last insert id: %w", err)
	}
	client.ID = id
	return nil
}

// UpdateClient updates an existing client record.
func (s *Store) UpdateClient(ctx context.Context, client *domain.Client) error {
	client.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
UPDATE clients SET name=?, username=?, password=?, enabled=?, updated_at=?
WHERE id=?`,
		client.Name, client.Username, client.Password, boolToInt(client.Enabled), formatTime(client.UpdatedAt), client.ID)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	return nil
}

// DeleteClient removes a client record.
func (s *Store) DeleteClient(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	return nil
}

// GetClient returns a client by ID.
func (s *Store) GetClient(ctx context.Context, id int64) (*domain.Client, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, vpn_id, name, username, password, enabled, created_at, updated_at
FROM clients WHERE id=?`, id)
	return scanClient(row)
}

// GetClientByName returns a client by VPN ID and name.
func (s *Store) GetClientByName(ctx context.Context, vpnID int64, name string) (*domain.Client, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, vpn_id, name, username, password, enabled, created_at, updated_at
FROM clients WHERE vpn_id=? AND name=?`, vpnID, name)
	return scanClient(row)
}

// ListClientsByVPN returns all clients for a VPN.
func (s *Store) ListClientsByVPN(ctx context.Context, vpnID int64) (_ []domain.Client, err error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, vpn_id, name, username, password, enabled, created_at, updated_at
FROM clients WHERE vpn_id=? ORDER BY name`, vpnID)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer s.closeRowsOnReturn(rows, &err)
	var clients []domain.Client
	for rows.Next() {
		client, err := s.scanClientFromRows(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, *client)
	}
	return clients, rows.Err()
}

// ListEnabledClientsByVPN returns enabled clients for a VPN.
func (s *Store) ListEnabledClientsByVPN(ctx context.Context, vpnID int64) (_ []domain.Client, err error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, vpn_id, name, username, password, enabled, created_at, updated_at
FROM clients WHERE vpn_id=? AND enabled=1 ORDER BY name`, vpnID)
	if err != nil {
		return nil, fmt.Errorf("list enabled clients: %w", err)
	}
	defer s.closeRowsOnReturn(rows, &err)
	var clients []domain.Client
	for rows.Next() {
		client, err := s.scanClientFromRows(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, *client)
	}
	return clients, rows.Err()
}

// SaveRevision stores a sing-box config revision for rollback.
func (s *Store) SaveRevision(ctx context.Context, singboxJSON []byte) (int64, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO config_revisions (singbox_json, created_at) VALUES (?, ?)`,
		string(singboxJSON), formatTime(now))
	if err != nil {
		return 0, fmt.Errorf("save revision: %w", err)
	}
	return s.lastInsertID(result)
}

// LatestRevision returns the most recent config revision.
func (s *Store) LatestRevision(ctx context.Context) ([]byte, int64, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, singbox_json FROM config_revisions ORDER BY id DESC LIMIT 1`)
	var id int64
	var jsonStr string
	if err := row.Scan(&id, &jsonStr); err != nil {
		if err == sql.ErrNoRows {
			return nil, 0, sql.ErrNoRows
		}
		return nil, 0, err
	}
	return []byte(jsonStr), id, nil
}

// PreviousRevision returns the second-most recent config revision.
func (s *Store) PreviousRevision(ctx context.Context) ([]byte, int64, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, singbox_json FROM config_revisions ORDER BY id DESC LIMIT 1 OFFSET 1`)
	var id int64
	var jsonStr string
	if err := row.Scan(&id, &jsonStr); err != nil {
		return nil, 0, err
	}
	return []byte(jsonStr), id, nil
}

func (s *Store) scanClientFromRows(rows *sql.Rows) (*domain.Client, error) {
	if s.ScanClientRow != nil {
		return s.ScanClientRow(rows)
	}
	return scanClientRow(rows)
}

func (s *Store) deleteVPNRecord(ctx context.Context, id int64) (sql.Result, error) {
	if s.DeleteVPNRecord != nil {
		return s.DeleteVPNRecord(ctx, id)
	}
	return s.db.ExecContext(ctx, `DELETE FROM vpns WHERE id=?`, id)
}

func (s *Store) lastInsertID(result sql.Result) (int64, error) {
	if s.LastInsertID != nil {
		return s.LastInsertID(result)
	}
	return result.LastInsertId()
}

func (s *Store) rowsAffected(result sql.Result) (int64, error) {
	if s.RowsAffected != nil {
		return s.RowsAffected(result)
	}
	return result.RowsAffected()
}

type scanner interface {
	Scan(dest ...any) error
}

// scanVPN reads a VPN row from a SQL scanner.
func scanVPN(row scanner) (*domain.VPN, error) {
	var vpn domain.VPN
	var enabled int
	var listenJSON, protocolJSON, createdAt, updatedAt string
	err := row.Scan(&vpn.ID, &vpn.Name, &vpn.Protocol, &vpn.Tag, &enabled, &vpn.ClientHost, &listenJSON, &protocolJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	vpn.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(listenJSON), &vpn.Listen); err != nil {
		return nil, fmt.Errorf("unmarshal listen: %w", err)
	}
	vpn.ProtocolData = []byte(protocolJSON)
	vpn.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	vpn.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &vpn, nil
}

// scanVPNRow reads a VPN row from an active SQL rows iterator.
func scanVPNRow(rows *sql.Rows) (*domain.VPN, error) {
	return scanVPN(rows)
}

// scanClient reads a client row from a SQL scanner.
func scanClient(row scanner) (*domain.Client, error) {
	var client domain.Client
	var enabled int
	var createdAt, updatedAt string
	err := row.Scan(&client.ID, &client.VPNID, &client.Name, &client.Username, &client.Password, &enabled, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	client.Enabled = enabled == 1
	client.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	client.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &client, nil
}

// scanClientRow reads a client row from an active SQL rows iterator.
func scanClientRow(rows *sql.Rows) (*domain.Client, error) {
	return scanClient(rows)
}

// boolToInt converts a bool to a SQLite integer flag.
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// formatTime serializes a timestamp for SQLite storage.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func (s *Store) tableInfoRowsErr(rows *sql.Rows) error {
	if s.TableInfoRowsErr != nil {
		return s.TableInfoRowsErr(rows)
	}
	return rows.Err()
}

func (s *Store) closeTableInfoRows(rows *sql.Rows) error {
	if s.CloseRows != nil {
		return s.CloseRows(rows)
	}
	return rows.Close()
}

func (s *Store) closeRowsOnReturn(rows *sql.Rows, err *error) {
	var cerr error
	if s.CloseRows != nil {
		cerr = s.CloseRows(rows)
	} else {
		cerr = rows.Close()
	}
	if cerr != nil && *err == nil {
		*err = cerr
	}
}
