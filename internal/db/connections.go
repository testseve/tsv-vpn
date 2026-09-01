package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")

type Connection struct {
	ID            int64
	Name          string
	GatewayHost   string
	PPPUsername   string
	RemoteSubnets []string
	HealthCheckIP string
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Secrets struct {
	PSK         string
	PPPPassword string
}

const connectionColumns = `id, name, gateway_host, ppp_username, remote_subnets,
	COALESCE(health_check_ip, ''), enabled, created_at, updated_at`

func (s *Store) ListConnections() ([]Connection, error) {
	rows, err := s.db.Query(`SELECT ` + connectionColumns + ` FROM connections ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []Connection
	for rows.Next() {
		conn, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, rows.Err()
}

func (s *Store) Connection(id int64) (Connection, error) {
	row := s.db.QueryRow(`SELECT `+connectionColumns+` FROM connections WHERE id = ?`, id)
	conn, err := scanConnection(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, fmt.Errorf("connection %d: %w", id, ErrNotFound)
	}
	return conn, err
}

func (s *Store) ConnectionSecrets(id int64) (Secrets, error) {
	var psk, password []byte
	err := s.db.QueryRow(`SELECT psk_ciphertext, ppp_password_ciphertext FROM connections WHERE id = ?`, id).
		Scan(&psk, &password)
	if errors.Is(err, sql.ErrNoRows) {
		return Secrets{}, fmt.Errorf("connection %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return Secrets{}, err
	}

	var secrets Secrets
	if secrets.PSK, err = s.cipher.Decrypt(psk); err != nil {
		return Secrets{}, fmt.Errorf("connection %d psk: %w", id, err)
	}
	if secrets.PPPPassword, err = s.cipher.Decrypt(password); err != nil {
		return Secrets{}, fmt.Errorf("connection %d ppp password: %w", id, err)
	}
	return secrets, nil
}

func (s *Store) CreateConnection(conn Connection, secrets Secrets) (int64, error) {
	if err := validateConnection(conn); err != nil {
		return 0, err
	}
	if secrets.PSK == "" || secrets.PPPPassword == "" {
		return 0, fmt.Errorf("psk and ppp password are required")
	}
	if err := ValidateSecrets(secrets); err != nil {
		return 0, err
	}
	if err := s.checkRouteConflicts(conn); err != nil {
		return 0, err
	}

	psk, err := s.cipher.Encrypt(secrets.PSK)
	if err != nil {
		return 0, err
	}
	password, err := s.cipher.Encrypt(secrets.PPPPassword)
	if err != nil {
		return 0, err
	}

	timestamp := now()
	result, err := s.db.Exec(`INSERT INTO connections
		(name, gateway_host, psk_ciphertext, ppp_username, ppp_password_ciphertext,
		 remote_subnets, health_check_ip, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conn.Name, conn.GatewayHost, psk, conn.PPPUsername, password,
		joinSubnets(conn.RemoteSubnets), nullable(conn.HealthCheckIP), conn.Enabled, timestamp, timestamp)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// Blank secret fields keep the stored ciphertext; the UI never reads a
// secret back out.
func (s *Store) UpdateConnection(conn Connection, secrets Secrets) error {
	if err := validateConnection(conn); err != nil {
		return err
	}
	if err := ValidateSecrets(secrets); err != nil {
		return err
	}
	if _, err := s.Connection(conn.ID); err != nil {
		return err
	}
	if err := s.checkRouteConflicts(conn); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`UPDATE connections SET name = ?, gateway_host = ?, ppp_username = ?,
		remote_subnets = ?, health_check_ip = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		conn.Name, conn.GatewayHost, conn.PPPUsername, joinSubnets(conn.RemoteSubnets),
		nullable(conn.HealthCheckIP), conn.Enabled, now(), conn.ID); err != nil {
		return err
	}
	if secrets.PSK != "" {
		psk, err := s.cipher.Encrypt(secrets.PSK)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE connections SET psk_ciphertext = ? WHERE id = ?`, psk, conn.ID); err != nil {
			return err
		}
	}
	if secrets.PPPPassword != "" {
		password, err := s.cipher.Encrypt(secrets.PPPPassword)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE connections SET ppp_password_ciphertext = ? WHERE id = ?`, password, conn.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetConnectionEnabled(id int64, enabled bool) error {
	result, err := s.db.Exec(`UPDATE connections SET enabled = ?, updated_at = ? WHERE id = ?`,
		enabled, now(), id)
	if err != nil {
		return err
	}
	return checkAffected(result, fmt.Sprintf("connection %d", id))
}

func (s *Store) SetHealthCheckIP(id int64, ip string) error {
	if ip != "" {
		if _, err := ParseIP(ip); err != nil {
			return err
		}
	}
	result, err := s.db.Exec(`UPDATE connections SET health_check_ip = ?, updated_at = ? WHERE id = ?`,
		nullable(ip), now(), id)
	if err != nil {
		return err
	}
	return checkAffected(result, fmt.Sprintf("connection %d", id))
}

func (s *Store) DeleteConnection(id int64) error {
	result, err := s.db.Exec(`DELETE FROM connections WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(result, fmt.Sprintf("connection %d", id))
}

func (s *Store) checkRouteConflicts(conn Connection) error {
	candidates, err := ParseSubnets(conn.RemoteSubnets)
	if err != nil {
		return err
	}
	claimed, err := s.claimedSubnets(conn.ID)
	if err != nil {
		return err
	}
	return CheckOverlap(candidates, claimed)
}

func (s *Store) claimedSubnets(exceptConnection int64) ([]Claim, error) {
	conns, err := s.ListConnections()
	if err != nil {
		return nil, err
	}
	var claimed []Claim
	for _, conn := range conns {
		if conn.ID == exceptConnection {
			continue
		}
		for _, subnet := range conn.RemoteSubnets {
			prefix, err := ParseSubnet(subnet)
			if err != nil {
				return nil, err
			}
			claimed = append(claimed, Claim{Owner: "connection " + conn.Name, Prefix: prefix})
		}
	}

	locals, err := s.ListLocalSubnets()
	if err != nil {
		return nil, err
	}
	for _, local := range locals {
		prefix, err := ParseSubnet(local.CIDR)
		if err != nil {
			return nil, err
		}
		claimed = append(claimed, Claim{Owner: "local subnet " + local.CIDR, Prefix: prefix})
	}
	return claimed, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanConnection(row scanner) (Connection, error) {
	var (
		conn                 Connection
		subnets              string
		createdAt, updatedAt string
	)
	if err := row.Scan(&conn.ID, &conn.Name, &conn.GatewayHost, &conn.PPPUsername, &subnets,
		&conn.HealthCheckIP, &conn.Enabled, &createdAt, &updatedAt); err != nil {
		return Connection{}, err
	}
	conn.RemoteSubnets = splitSubnets(subnets)
	conn.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	conn.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return conn, nil
}

func joinSubnets(subnets []string) string {
	canonical := make([]string, 0, len(subnets))
	for _, subnet := range subnets {
		prefix, err := ParseSubnet(subnet)
		if err != nil {
			canonical = append(canonical, strings.TrimSpace(subnet))
			continue
		}
		canonical = append(canonical, prefix.String())
	}
	return strings.Join(canonical, ",")
}

func splitSubnets(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, ",")
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func prefixesOf(subnets []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(subnets))
	for _, subnet := range subnets {
		if prefix, err := ParseSubnet(subnet); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}
