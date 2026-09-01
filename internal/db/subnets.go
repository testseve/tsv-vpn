package db

import (
	"database/sql"
	"fmt"
	"sort"
	"time"
)

type LocalSubnet struct {
	ID            int64
	CIDR          string
	Description   string
	HealthCheckIP string
	Enabled       bool
	CreatedAt     time.Time
	LastCheckAt   time.Time
	LastRTTMS     float64
	LastError     string
}

func (s *Store) ListLocalSubnets() ([]LocalSubnet, error) {
	rows, err := s.db.Query(`SELECT s.id, s.cidr, COALESCE(s.description, ''), COALESCE(s.health_check_ip, ''),
		s.enabled, s.created_at, st.last_check_at, st.last_rtt_ms, COALESCE(st.last_error, '')
		FROM local_subnets s LEFT JOIN local_subnet_status st ON st.subnet_id = s.id
		ORDER BY s.cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subnets []LocalSubnet
	for rows.Next() {
		var (
			subnet      LocalSubnet
			createdAt   string
			lastCheckAt sql.NullString
			rtt         sql.NullFloat64
		)
		if err := rows.Scan(&subnet.ID, &subnet.CIDR, &subnet.Description, &subnet.HealthCheckIP,
			&subnet.Enabled, &createdAt, &lastCheckAt, &rtt, &subnet.LastError); err != nil {
			return nil, err
		}
		subnet.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		subnet.LastCheckAt = parseTime(lastCheckAt)
		subnet.LastRTTMS = rtt.Float64
		subnets = append(subnets, subnet)
	}
	return subnets, rows.Err()
}

func (s *Store) CreateLocalSubnet(subnet LocalSubnet) (int64, error) {
	prefix, err := ParseSubnet(subnet.CIDR)
	if err != nil {
		return 0, err
	}
	claimed, err := s.claimedSubnets(0)
	if err != nil {
		return 0, err
	}
	if err := CheckOverlap(prefixesOf([]string{prefix.String()}), claimed); err != nil {
		return 0, err
	}
	if subnet.HealthCheckIP != "" {
		if _, err := ParseIP(subnet.HealthCheckIP); err != nil {
			return 0, err
		}
	}

	result, err := s.db.Exec(`INSERT INTO local_subnets (cidr, description, health_check_ip, enabled, created_at)
		VALUES (?, ?, ?, ?, ?)`, prefix.String(), nullable(subnet.Description), nullable(subnet.HealthCheckIP), subnet.Enabled, now())
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *Store) LocalSubnet(id int64) (LocalSubnet, error) {
	subnets, err := s.ListLocalSubnets()
	if err != nil {
		return LocalSubnet{}, err
	}
	for _, subnet := range subnets {
		if subnet.ID == id {
			return subnet, nil
		}
	}
	return LocalSubnet{}, fmt.Errorf("local subnet %d: %w", id, ErrNotFound)
}

func (s *Store) SetLocalSubnetHealthCheckIP(id int64, ip string) error {
	if ip != "" {
		if _, err := ParseIP(ip); err != nil {
			return err
		}
	}
	result, err := s.db.Exec(`UPDATE local_subnets SET health_check_ip = ? WHERE id = ?`, nullable(ip), id)
	if err != nil {
		return err
	}
	return checkAffected(result, fmt.Sprintf("local subnet %d", id))
}

// Like RecordCheck, but subnet checks have no connection row to update.
func (s *Store) RecordSubnetCheck(id int64, at time.Time, rtt time.Duration, failure string) error {
	_, err := s.db.Exec(`INSERT INTO local_subnet_status (subnet_id, last_check_at, last_rtt_ms, last_error)
		SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM local_subnets WHERE id = ?)
		ON CONFLICT(subnet_id) DO UPDATE SET
			last_check_at = excluded.last_check_at,
			last_rtt_ms = excluded.last_rtt_ms,
			last_error = excluded.last_error`,
		id, formatTime(at), nullableFloat(float64(rtt.Microseconds())/1000), nullable(failure), id)
	return err
}

func (s *Store) SetLocalSubnetEnabled(id int64, enabled bool) error {
	result, err := s.db.Exec(`UPDATE local_subnets SET enabled = ? WHERE id = ?`, enabled, id)
	if err != nil {
		return err
	}
	return checkAffected(result, fmt.Sprintf("local subnet %d", id))
}

func (s *Store) DeleteLocalSubnet(id int64) error {
	result, err := s.db.Exec(`DELETE FROM local_subnets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(result, fmt.Sprintf("local subnet %d", id))
}

// Local subnets ride the container's default route; only tunnel subnets get
// routes installed. Both are advertised.
func (s *Store) AdvertisedRoutes() ([]string, error) {
	conns, err := s.ListConnections()
	if err != nil {
		return nil, err
	}
	locals, err := s.ListLocalSubnets()
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var routes []string
	add := func(cidr string) {
		if seen[cidr] {
			return
		}
		seen[cidr] = true
		routes = append(routes, cidr)
	}
	for _, conn := range conns {
		if !conn.Enabled {
			continue
		}
		for _, subnet := range conn.RemoteSubnets {
			add(subnet)
		}
	}
	for _, local := range locals {
		if local.Enabled {
			add(local.CIDR)
		}
	}
	sort.Strings(routes)
	return routes, nil
}
