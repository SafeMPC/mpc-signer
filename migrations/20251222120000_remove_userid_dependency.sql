-- +migrate Up
-- 注意：backup_share_deliveries 表已删除（备份功能已移除）
ALTER TABLE IF EXISTS user_passkeys
    DROP CONSTRAINT IF EXISTS user_passkeys_pkey;

ALTER TABLE IF EXISTS user_passkeys
    DROP COLUMN IF EXISTS user_id;

ALTER TABLE IF EXISTS user_passkeys
    ADD PRIMARY KEY (credential_id);

-- +migrate Down
-- 注意：这里无法简单恢复数据，仅为结构回滚
ALTER TABLE IF EXISTS user_passkeys
    ADD COLUMN IF NOT EXISTS user_id VARCHAR(255) NOT NULL DEFAULT '';

ALTER TABLE IF EXISTS user_passkeys
    DROP CONSTRAINT IF EXISTS user_passkeys_pkey;

ALTER TABLE IF EXISTS user_passkeys
    ADD PRIMARY KEY (user_id, credential_id);

