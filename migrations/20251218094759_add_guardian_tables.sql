-- +migrate Up
-- Passkey 存储表 (替代原有的 user_auth_keys)
-- 注意：signing_policies 表已删除（团队签功能已移除）
CREATE TABLE user_passkeys (
    user_id varchar(255) NOT NULL,
    credential_id varchar(512) NOT NULL,
    public_key text NOT NULL, -- COSE Key Format (Hex/Base64)
    device_name varchar(255),
    created_at timestamp with time zone DEFAULT NOW(),
    PRIMARY KEY (user_id, credential_id)
);

-- +migrate Down
DROP TABLE user_passkeys;

