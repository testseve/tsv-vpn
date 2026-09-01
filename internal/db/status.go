package db

import (
	"database/sql"
	"errors"
	"time"
)

type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateUp           State = "up"
	StateFailed       State = "failed"
)

type Status struct {
	ConnectionID int64
	State        State
	Iface        string
	LocalIP      string
	PeerIP       string
	ConnectedAt  time.Time
	LastCheckAt  time.Time
	LastRTTMS    float64
	LastError    string
}

func (s *Store) Status(connectionID int64) (Status, error) {
	var (
		status                   Status
		connectedAt, lastCheckAt sql.NullString
		rtt                      sql.NullFloat64
	)
	err := s.db.QueryRow(`SELECT connection_id, state, COALESCE(iface, ''), COALESCE(local_ip, ''),
		COALESCE(peer_ip, ''), connected_at, last_check_at, last_rtt_ms, COALESCE(last_error, '')
		FROM connection_status WHERE connection_id = ?`, connectionID).
		Scan(&status.ConnectionID, &status.State, &status.Iface, &status.LocalIP, &status.PeerIP,
			&connectedAt, &lastCheckAt, &rtt, &status.LastError)
	if errors.Is(err, sql.ErrNoRows) {
		return Status{ConnectionID: connectionID, State: StateDisconnected}, nil
	}
	if err != nil {
		return Status{}, err
	}
	status.ConnectedAt = parseTime(connectedAt)
	status.LastCheckAt = parseTime(lastCheckAt)
	status.LastRTTMS = rtt.Float64
	return status, nil
}

// The last status write of a deleted connection has nowhere to land; drop it
// instead of failing.
func (s *Store) SetStatus(status Status) error {
	_, err := s.db.Exec(`INSERT INTO connection_status
		(connection_id, state, iface, local_ip, peer_ip, connected_at, last_check_at, last_rtt_ms, last_error)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM connections WHERE id = ?)
		ON CONFLICT(connection_id) DO UPDATE SET
			state = excluded.state,
			iface = excluded.iface,
			local_ip = excluded.local_ip,
			peer_ip = excluded.peer_ip,
			connected_at = excluded.connected_at,
			last_check_at = excluded.last_check_at,
			last_rtt_ms = excluded.last_rtt_ms,
			last_error = excluded.last_error`,
		status.ConnectionID, string(status.State), nullable(status.Iface),
		nullable(status.LocalIP), nullable(status.PeerIP),
		formatTime(status.ConnectedAt), formatTime(status.LastCheckAt),
		nullableFloat(status.LastRTTMS), nullable(status.LastError), status.ConnectionID)
	return err
}

// Health checks write their own columns and leave the rest of the row to the
// reconciler.
func (s *Store) RecordCheck(connectionID int64, at time.Time, rtt time.Duration, failure string) error {
	_, err := s.db.Exec(`UPDATE connection_status
		SET last_check_at = ?, last_rtt_ms = ?, last_error = ?
		WHERE connection_id = ?`,
		formatTime(at), nullableFloat(float64(rtt.Microseconds())/1000), nullable(failure), connectionID)
	return err
}

func parseTime(value sql.NullString) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	parsed, _ := time.Parse(time.RFC3339, value.String)
	return parsed
}

func formatTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC().Format(time.RFC3339)
}

func nullableFloat(value float64) any {
	if value == 0 {
		return nil
	}
	return value
}
