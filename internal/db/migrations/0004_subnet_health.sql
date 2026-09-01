ALTER TABLE local_subnets ADD COLUMN health_check_ip TEXT;

CREATE TABLE local_subnet_status (
    subnet_id INTEGER PRIMARY KEY REFERENCES local_subnets(id) ON DELETE CASCADE,
    last_check_at TEXT,
    last_rtt_ms REAL,
    last_error TEXT
);
