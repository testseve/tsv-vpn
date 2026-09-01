package db

import (
	"database/sql"
	"errors"
)

func (s *Store) Setting(name string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE name = ?`, name).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *Store) DeleteSetting(name string) error {
	_, err := s.db.Exec(`DELETE FROM settings WHERE name = ?`, name)
	return err
}

const exitNodeSetting = "exit_node"

func (s *Store) ExitNode() (bool, error) {
	value, err := s.Setting(exitNodeSetting)
	return value == "1", err
}

func (s *Store) SetExitNode(enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	return s.SetSetting(exitNodeSetting, value)
}

func (s *Store) SetSetting(name, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (name, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		name, value, now())
	return err
}
