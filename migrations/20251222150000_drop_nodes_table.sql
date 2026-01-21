-- +migrate Up
DROP TABLE IF EXISTS nodes;

-- +migrate Down
CREATE TABLE nodes (
    node_id varchar(255) PRIMARY KEY,
    node_type varchar(50) NOT NULL,
    endpoint varchar(255) NOT NULL,
    public_key text,
    status varchar(50) NOT NULL,
    capabilities jsonb,
    metadata jsonb,
    registered_at timestamptz NOT NULL DEFAULT NOW(),
    last_heartbeat timestamptz
);

CREATE INDEX idx_nodes_type ON nodes (node_type);

CREATE INDEX idx_nodes_status ON nodes (status);

