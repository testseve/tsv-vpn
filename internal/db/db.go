package db

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"tsv-vpn/internal/crypto"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

func Open(path string, cipher *crypto.Cipher) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc applies pragmas per connection and SQLite serializes writers
	// anyway; one connection rules out SQLITE_BUSY.
	handle.SetMaxOpenConns(1)

	store := &Store{db: handle, cipher: cipher}
	if err := store.migrate(); err != nil {
		handle.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)

	// Versions come from the NNNN filename prefix, so a removed or renamed
	// file fails loudly instead of shifting later migrations.
	for i, name := range names {
		if v, err := migrationVersion(name); err != nil {
			return err
		} else if v != i+1 {
			return fmt.Errorf("migration %s: want version %04d", name, i+1)
		}
	}

	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(names) {
		return fmt.Errorf("database schema version %d is newer than this binary knows (%d)", version, len(names))
	}
	for i, name := range names[version:] {
		statements, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if err := s.applyMigration(name, string(statements), version+i+1); err != nil {
			return err
		}
	}
	return nil
}

func migrationVersion(name string) (int, error) {
	base := path.Base(name)
	prefix, _, ok := strings.Cut(base, "_")
	if !ok {
		return 0, fmt.Errorf("migration %s: name must start with NNNN_", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("migration %s: name must start with NNNN_", name)
	}
	return version, nil
}

func (s *Store) applyMigration(name, statements string, version int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(statements); err != nil {
		return fmt.Errorf("migration %s: %w", name, err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func checkAffected(result sql.Result, subject string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%s: %w", subject, ErrNotFound)
	}
	return nil
}
