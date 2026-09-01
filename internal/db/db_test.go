package db

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tsv-vpn/internal/crypto"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "test.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func sampleConnection() (Connection, Secrets) {
	return Connection{
			Name:          "example",
			GatewayHost:   "vpn.example.com",
			PPPUsername:   "user",
			RemoteSubnets: []string{"198.51.100.0/24"},
			HealthCheckIP: "198.51.100.10",
			Enabled:       true,
		}, Secrets{
			PSK:         "psk-canary-value",
			PPPPassword: "ppp-canary-value",
		}
}

func TestConnectionRoundTrip(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()

	id, err := store.CreateConnection(conn, secrets)
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.Connection(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != conn.Name || got.GatewayHost != conn.GatewayHost || got.HealthCheckIP != conn.HealthCheckIP {
		t.Fatalf("got %+v, want %+v", got, conn)
	}
	if len(got.RemoteSubnets) != 1 || got.RemoteSubnets[0] != "198.51.100.0/24" {
		t.Fatalf("subnets: got %v", got.RemoteSubnets)
	}
	if !got.Enabled || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}

	gotSecrets, err := store.ConnectionSecrets(id)
	if err != nil {
		t.Fatal(err)
	}
	if gotSecrets != secrets {
		t.Fatalf("got %+v, want %+v", gotSecrets, secrets)
	}
}

func TestSecretsAreEncryptedAtRest(t *testing.T) {
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.db")
	store, err := Open(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	conn, secrets := sampleConnection()
	if _, err := store.CreateConnection(conn, secrets); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"", "-wal"} {
		raw, err := os.ReadFile(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{secrets.PSK, secrets.PPPPassword} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("%s contains plaintext secret %q", path+suffix, secret)
			}
		}
	}
}

func TestUpdateKeepsSecretsWhenBlank(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	id, err := store.CreateConnection(conn, secrets)
	if err != nil {
		t.Fatal(err)
	}

	conn.ID = id
	conn.GatewayHost = "other.example.com"
	if err := store.UpdateConnection(conn, Secrets{}); err != nil {
		t.Fatal(err)
	}
	got, err := store.ConnectionSecrets(id)
	if err != nil {
		t.Fatal(err)
	}
	if got != secrets {
		t.Fatalf("got %+v, want %+v", got, secrets)
	}

	if err := store.UpdateConnection(conn, Secrets{PSK: "rotated"}); err != nil {
		t.Fatal(err)
	}
	got, err = store.ConnectionSecrets(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.PSK != "rotated" || got.PPPPassword != secrets.PPPPassword {
		t.Fatalf("got %+v", got)
	}
}

func TestCreateRejectsOverlappingSubnets(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	if _, err := store.CreateConnection(conn, secrets); err != nil {
		t.Fatal(err)
	}

	other := conn
	other.Name = "other"
	other.RemoteSubnets = []string{"198.51.100.128/25"}
	if _, err := store.CreateConnection(other, secrets); err == nil {
		t.Fatal("want overlap rejection against another connection")
	}

	if _, err := store.CreateLocalSubnet(LocalSubnet{CIDR: "198.51.100.0/25", Enabled: true}); err == nil {
		t.Fatal("want overlap rejection against a connection subnet")
	}

	if _, err := store.CreateLocalSubnet(LocalSubnet{CIDR: "192.0.2.0/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	third := conn
	third.Name = "third"
	third.RemoteSubnets = []string{"192.0.2.0/28"}
	if _, err := store.CreateConnection(third, secrets); err == nil {
		t.Fatal("want overlap rejection against a local subnet")
	}
}

func TestUpdateIgnoresItsOwnSubnets(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	id, err := store.CreateConnection(conn, secrets)
	if err != nil {
		t.Fatal(err)
	}
	conn.ID = id
	if err := store.UpdateConnection(conn, Secrets{}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRejectsInvalidInput(t *testing.T) {
	store := testStore(t)
	valid, secrets := sampleConnection()

	cases := map[string]func(*Connection){
		"bad name":      func(c *Connection) { c.Name = "Not Valid" },
		"no gateway":    func(c *Connection) { c.GatewayHost = "" },
		"no user":       func(c *Connection) { c.PPPUsername = "" },
		"no subnets":    func(c *Connection) { c.RemoteSubnets = nil },
		"bad subnet":    func(c *Connection) { c.RemoteSubnets = []string{"198.51.100.0"} },
		"host bits":     func(c *Connection) { c.RemoteSubnets = []string{"198.51.100.5/24"} },
		"bad health ip": func(c *Connection) { c.HealthCheckIP = "not-an-ip" },
	}
	for name, mutate := range cases {
		conn := valid
		mutate(&conn)
		if _, err := store.CreateConnection(conn, secrets); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}

	if _, err := store.CreateConnection(valid, Secrets{PSK: "only"}); err == nil {
		t.Fatal("want error when the ppp password is missing")
	}
}

func TestDeleteConnection(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	id, err := store.CreateConnection(conn, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetStatus(Status{ConnectionID: id, State: StateUp, Iface: "ppp0"}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteConnection(id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Connection(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	if err := store.DeleteConnection(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}

	status, err := store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateDisconnected {
		t.Fatalf("status survived the delete: %+v", status)
	}
}

func TestStatusUpsert(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	id, err := store.CreateConnection(conn, secrets)
	if err != nil {
		t.Fatal(err)
	}

	status, err := store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateDisconnected {
		t.Fatalf("unset status: got %q", status.State)
	}

	if err := store.SetStatus(Status{ConnectionID: id, State: StateUp, Iface: "ppp0", LastRTTMS: 12.5}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetStatus(Status{ConnectionID: id, State: StateFailed, LastError: "IKE authentication failed"}); err != nil {
		t.Fatal(err)
	}
	status, err = store.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateFailed || status.LastError != "IKE authentication failed" || status.Iface != "" {
		t.Fatalf("got %+v", status)
	}
}

func TestAdvertisedRoutes(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	if _, err := store.CreateConnection(conn, secrets); err != nil {
		t.Fatal(err)
	}
	disabled := conn
	disabled.Name = "disabled"
	disabled.RemoteSubnets = []string{"203.0.113.0/24"}
	disabled.Enabled = false
	if _, err := store.CreateConnection(disabled, secrets); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLocalSubnet(LocalSubnet{CIDR: "192.0.2.0/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	off, err := store.CreateLocalSubnet(LocalSubnet{CIDR: "10.10.0.0/16", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLocalSubnetEnabled(off, false); err != nil {
		t.Fatal(err)
	}

	routes, err := store.AdvertisedRoutes()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0/24", "198.51.100.0/24"}
	if strings.Join(routes, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", routes, want)
	}
}

func TestLocalSubnetLifecycle(t *testing.T) {
	store := testStore(t)
	id, err := store.CreateLocalSubnet(LocalSubnet{CIDR: "192.0.2.0/24", Description: "lan", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	subnets, err := store.ListLocalSubnets()
	if err != nil {
		t.Fatal(err)
	}
	if len(subnets) != 1 || subnets[0].Description != "lan" || !subnets[0].Enabled {
		t.Fatalf("got %+v", subnets)
	}
	if err := store.DeleteLocalSubnet(id); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLocalSubnet(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	key, err := crypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.db")
	for range 2 {
		store, err := Open(path, cipher)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListConnections(); err != nil {
			t.Fatal(err)
		}
		store.Close()
	}
}

func TestStatusForADeletedConnectionIsDropped(t *testing.T) {
	store := testStore(t)
	conn, secrets := sampleConnection()
	id, err := store.CreateConnection(conn, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteConnection(id); err != nil {
		t.Fatal(err)
	}

	if err := store.SetStatus(Status{ConnectionID: id, State: StateDisconnected}); err != nil {
		t.Fatalf("writing status for a deleted connection: %v", err)
	}
}
