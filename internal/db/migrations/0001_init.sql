CREATE TABLE connections (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    gateway_host TEXT NOT NULL,
    psk_ciphertext BLOB NOT NULL,
    ppp_username TEXT NOT NULL,
    ppp_password_ciphertext BLOB NOT NULL,
    remote_subnets TEXT NOT NULL,
    health_check_ip TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE connection_status (
    connection_id INTEGER PRIMARY KEY REFERENCES connections(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    iface TEXT,
    connected_at TEXT,
    last_check_at TEXT,
    last_rtt_ms REAL,
    last_error TEXT
);

CREATE TABLE local_subnets (
    id INTEGER PRIMARY KEY,
    cidr TEXT NOT NULL UNIQUE,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
