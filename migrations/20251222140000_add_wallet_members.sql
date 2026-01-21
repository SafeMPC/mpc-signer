-- +migrate Up
CREATE TABLE wallet_members (
    wallet_id varchar(255) NOT NULL,
    credential_id varchar(512) NOT NULL,
    role varchar(50) NOT NULL DEFAULT 'member', -- 'admin', 'member'
    created_at timestamp with time zone DEFAULT NOW(),
    PRIMARY KEY (wallet_id, credential_id)
);

-- +migrate Down
DROP TABLE wallet_members;

