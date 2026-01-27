package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
)

// PostgreSQLStore PostgreSQL存储实现
type PostgreSQLStore struct {
	db *sql.DB
}

// NewPostgreSQLStore 创建PostgreSQL存储实例
func NewPostgreSQLStore(db *sql.DB) MetadataStore {
	return &PostgreSQLStore{db: db}
}

// SaveKeyMetadata 保存密钥元数据
func (s *PostgreSQLStore) SaveKeyMetadata(ctx context.Context, key *KeyMetadata) error {
	tagsJSON, err := json.Marshal(key.Tags)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tags")
	}

	query := `
		INSERT INTO keys (
			key_id, public_key, algorithm, curve, threshold, total_nodes,
			chain_type, chain_code, address, status, description, tags, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (key_id) DO UPDATE SET
			public_key = EXCLUDED.public_key,
			algorithm = EXCLUDED.algorithm,
			curve = EXCLUDED.curve,
			threshold = EXCLUDED.threshold,
			total_nodes = EXCLUDED.total_nodes,
			chain_type = EXCLUDED.chain_type,
			chain_code = EXCLUDED.chain_code,
			address = EXCLUDED.address,
			status = EXCLUDED.status,
			description = EXCLUDED.description,
			tags = EXCLUDED.tags,
			updated_at = EXCLUDED.updated_at
	`

	result, err := s.db.ExecContext(ctx, query,
		key.KeyID, key.PublicKey, key.Algorithm, key.Curve, key.Threshold, key.TotalNodes,
		key.ChainType, key.ChainCode, key.Address, key.Status, key.Description, tagsJSON,
		key.CreatedAt, key.UpdatedAt,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to save key metadata for key_id: %s", key.KeyID)
	}

	// 验证插入是否成功
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}
	if rowsAffected == 0 {
		return errors.Errorf("no rows affected when saving key metadata for key_id: %s", key.KeyID)
	}

	return nil
}

// GetKeyMetadata 获取密钥元数据
func (s *PostgreSQLStore) GetKeyMetadata(ctx context.Context, keyID string) (*KeyMetadata, error) {
	query := `
		SELECT key_id, public_key, algorithm, curve, threshold, total_nodes,
			chain_type, chain_code, address, status, description, tags, created_at, updated_at, deletion_date
		FROM keys
		WHERE key_id = $1
	`

	var key KeyMetadata
	var tagsJSON []byte
	var deletionDate sql.NullTime
	var chainCode sql.NullString

	err := s.db.QueryRowContext(ctx, query, keyID).Scan(
		&key.KeyID, &key.PublicKey, &key.Algorithm, &key.Curve, &key.Threshold, &key.TotalNodes,
		&key.ChainType, &chainCode, &key.Address, &key.Status, &key.Description, &tagsJSON,
		&key.CreatedAt, &key.UpdatedAt, &deletionDate,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("key not found")
		}
		return nil, errors.Wrap(err, "failed to get key metadata")
	}

	if chainCode.Valid {
		key.ChainCode = chainCode.String
	}

	if len(tagsJSON) > 0 {
		if err := json.Unmarshal(tagsJSON, &key.Tags); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal tags")
		}
	}
	if tagsJSON == nil {
		key.Tags = make(map[string]string)
	}

	if deletionDate.Valid {
		key.DeletionDate = &deletionDate.Time
	}

	return &key, nil
}

// UpdateKeyMetadata 更新密钥元数据
func (s *PostgreSQLStore) UpdateKeyMetadata(ctx context.Context, key *KeyMetadata) error {
	tagsJSON, err := json.Marshal(key.Tags)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tags")
	}

	query := `
		UPDATE keys SET
			public_key = $2,
			algorithm = $3,
			curve = $4,
			threshold = $5,
			total_nodes = $6,
			chain_type = $7,
			chain_code = $8,
			address = $9,
			status = $10,
			description = $11,
			tags = $12,
			updated_at = $13,
			deletion_date = $14
		WHERE key_id = $1
	`

	var deletionDate interface{}
	if key.DeletionDate != nil {
		deletionDate = *key.DeletionDate
	}

	_, err = s.db.ExecContext(ctx, query,
		key.KeyID, key.PublicKey, key.Algorithm, key.Curve, key.Threshold, key.TotalNodes,
		key.ChainType, key.ChainCode, key.Address, key.Status, key.Description, tagsJSON,
		key.UpdatedAt, deletionDate,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update key metadata")
	}

	return nil
}

// DeleteKeyMetadata 删除密钥元数据
func (s *PostgreSQLStore) DeleteKeyMetadata(ctx context.Context, keyID string) error {
	query := `DELETE FROM keys WHERE key_id = $1`
	_, err := s.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return errors.Wrap(err, "failed to delete key metadata")
	}
	return nil
}

// ListKeys 列出密钥
func (s *PostgreSQLStore) ListKeys(ctx context.Context, filter *KeyFilter) ([]*KeyMetadata, error) {
	if filter == nil {
		filter = &KeyFilter{Limit: 50}
	}
	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	query := `SELECT key_id, public_key, algorithm, curve, threshold, total_nodes,
		chain_type, chain_code, address, status, description, tags, created_at, updated_at, deletion_date
		FROM keys WHERE 1=1`
	args := []interface{}{}
	argIndex := 1

	if filter.ChainType != "" {
		query += ` AND chain_type = $` + string(rune('0'+argIndex))
		args = append(args, filter.ChainType)
		argIndex++
	}

	if filter.Status != "" {
		query += ` AND status = $` + string(rune('0'+argIndex))
		args = append(args, filter.Status)
		argIndex++
	}

	query += ` ORDER BY created_at DESC LIMIT $` + string(rune('0'+argIndex)) + ` OFFSET $` + string(rune('0'+argIndex+1))
	args = append(args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list keys")
	}
	defer rows.Close()

	var keys []*KeyMetadata
	for rows.Next() {
		var key KeyMetadata
		var tagsJSON []byte
		var deletionDate sql.NullTime
		var chainCode sql.NullString

		err := rows.Scan(
			&key.KeyID, &key.PublicKey, &key.Algorithm, &key.Curve, &key.Threshold, &key.TotalNodes,
			&key.ChainType, &chainCode, &key.Address, &key.Status, &key.Description, &tagsJSON,
			&key.CreatedAt, &key.UpdatedAt, &deletionDate,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan key")
		}

		if chainCode.Valid {
			key.ChainCode = chainCode.String
		}

		if len(tagsJSON) > 0 {
			if err := json.Unmarshal(tagsJSON, &key.Tags); err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal tags")
			}
		}
		if tagsJSON == nil {
			key.Tags = make(map[string]string)
		}

		if deletionDate.Valid {
			key.DeletionDate = &deletionDate.Time
		}

		keys = append(keys, &key)
	}

	return keys, nil
}

// SavePasskey 保存用户 Passkey
func (s *PostgreSQLStore) SavePasskey(ctx context.Context, passkey *Passkey) error {
	query := `
		INSERT INTO passkeys (credential_id, public_key, device_name, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (credential_id) DO UPDATE SET
			public_key = EXCLUDED.public_key,
			device_name = EXCLUDED.device_name
	`

	_, err := s.db.ExecContext(ctx, query,
		passkey.CredentialID, passkey.PublicKey, passkey.DeviceName, passkey.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, "failed to save user passkey")
	}

	return nil
}

// GetPasskey 获取用户 Passkey
func (s *PostgreSQLStore) GetPasskey(ctx context.Context, credentialID string) (*Passkey, error) {
	query := `
		SELECT credential_id, public_key, device_name, created_at
		FROM passkeys
		WHERE credential_id = $1
	`

	var passkey Passkey
	err := s.db.QueryRowContext(ctx, query, credentialID).Scan(
		&passkey.CredentialID, &passkey.PublicKey, &passkey.DeviceName, &passkey.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("passkey not found")
		}
		return nil, errors.Wrap(err, "failed to get user passkey")
	}

	return &passkey, nil
}

// SaveNode 保存节点信息 (Deprecated: Use Consul)
// func (s *PostgreSQLStore) SaveNode(ctx context.Context, node *NodeInfo) error {
// 	return errors.New("SaveNode is deprecated, use Consul")
// }

// GetNode 获取节点信息 (Deprecated: Use Consul)
// func (s *PostgreSQLStore) GetNode(ctx context.Context, nodeID string) (*NodeInfo, error) {
// 	return nil, errors.New("GetNode is deprecated, use Consul")
// }

// UpdateNode 更新节点信息 (Deprecated: Use Consul)
// func (s *PostgreSQLStore) UpdateNode(ctx context.Context, node *NodeInfo) error {
// 	return errors.New("UpdateNode is deprecated, use Consul")
// }

// UpdateNodeHeartbeat 更新节点心跳 (Deprecated: Use Consul)
// func (s *PostgreSQLStore) UpdateNodeHeartbeat(ctx context.Context, nodeID string) error {
// 	return errors.New("UpdateNodeHeartbeat is deprecated, use Consul")
// }

// SaveSigningSession 保存签名会话
func (s *PostgreSQLStore) SaveSigningSession(ctx context.Context, session *SigningSession) error {
	// 记录保存的节点列表（用于调试）
	// 注意：storage 包没有导入 log，所以我们不能在这里记录日志
	// 但我们可以通过返回错误来提供信息

	participatingNodesJSON, err := json.Marshal(session.ParticipatingNodes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal participating nodes")
	}

	query := `
		INSERT INTO signing_sessions (
			session_id, key_id, protocol, status, threshold, total_nodes,
			participating_nodes, current_round, total_rounds, signature,
			created_at, completed_at, duration_ms
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (session_id) DO UPDATE SET
			key_id = EXCLUDED.key_id,
			protocol = EXCLUDED.protocol,
			status = EXCLUDED.status,
			threshold = EXCLUDED.threshold,
			total_nodes = EXCLUDED.total_nodes,
			participating_nodes = EXCLUDED.participating_nodes,
			current_round = EXCLUDED.current_round,
			total_rounds = EXCLUDED.total_rounds,
			signature = EXCLUDED.signature,
			completed_at = EXCLUDED.completed_at,
			duration_ms = EXCLUDED.duration_ms
	`

	var completedAt interface{}
	if session.CompletedAt != nil {
		completedAt = *session.CompletedAt
	}

	// 首先验证 key_id 是否存在（在同一个事务/连接中检查，避免事务隔离问题）
	var keyExists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM keys WHERE key_id = $1)`
	if err := s.db.QueryRowContext(ctx, checkQuery, session.KeyID).Scan(&keyExists); err != nil {
		// 如果查询失败，返回更详细的错误信息
		return errors.Wrapf(err, "failed to check if key_id %s exists in keys table", session.KeyID)
	}
	if !keyExists {
		// 记录详细的错误信息，包括可能的根因
		return errors.Errorf("key_id %s does not exist in keys table, cannot create signing session. This usually means: 1) the placeholder key was not created successfully, 2) the key was created in a different transaction that hasn't committed yet, or 3) there's a database connection/transaction isolation issue", session.KeyID)
	}

	_, err = s.db.ExecContext(ctx, query,
		session.SessionID, session.KeyID, session.Protocol, session.Status,
		session.Threshold, session.TotalNodes, participatingNodesJSON,
		session.CurrentRound, session.TotalRounds, session.Signature,
		session.CreatedAt, completedAt, session.DurationMs,
	)
	if err != nil {
		// 检查是否是外键约束错误
		errStr := err.Error()
		if strings.Contains(errStr, "foreign key") || strings.Contains(errStr, "violates foreign key constraint") {
			return errors.Wrapf(err, "failed to save signing session: foreign key constraint violation - key_id %s does not exist in keys table", session.KeyID)
		}
		// 检查是否是唯一约束错误
		if strings.Contains(errStr, "unique constraint") || strings.Contains(errStr, "duplicate key") {
			return errors.Wrapf(err, "failed to save signing session: unique constraint violation - session_id %s already exists", session.SessionID)
		}
		// 其他数据库错误
		return errors.Wrapf(err, "failed to save signing session (session_id: %s, key_id: %s)", session.SessionID, session.KeyID)
	}

	return nil
}

// GetSigningSession 获取签名会话
func (s *PostgreSQLStore) GetSigningSession(ctx context.Context, sessionID string) (*SigningSession, error) {
	query := `
		SELECT session_id, key_id, protocol, status, threshold, total_nodes,
			participating_nodes, current_round, total_rounds, signature,
			created_at, completed_at, duration_ms
		FROM signing_sessions
		WHERE session_id = $1
	`

	var session SigningSession
	var participatingNodesJSON []byte
	var completedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, sessionID).Scan(
		&session.SessionID, &session.KeyID, &session.Protocol, &session.Status,
		&session.Threshold, &session.TotalNodes, &participatingNodesJSON,
		&session.CurrentRound, &session.TotalRounds, &session.Signature,
		&session.CreatedAt, &completedAt, &session.DurationMs,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("session not found")
		}
		return nil, errors.Wrap(err, "failed to get signing session")
	}

	if len(participatingNodesJSON) > 0 {
		if err := json.Unmarshal(participatingNodesJSON, &session.ParticipatingNodes); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal participating nodes")
		}
	}
	if participatingNodesJSON == nil {
		session.ParticipatingNodes = []string{}
	}

	if completedAt.Valid {
		session.CompletedAt = &completedAt.Time
	}

	return &session, nil
}

// UpdateSigningSession 更新签名会话
func (s *PostgreSQLStore) UpdateSigningSession(ctx context.Context, session *SigningSession) error {
	participatingNodesJSON, err := json.Marshal(session.ParticipatingNodes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal participating nodes")
	}

	query := `
		UPDATE signing_sessions SET
			key_id = $2,
			protocol = $3,
			status = $4,
			threshold = $5,
			total_nodes = $6,
			participating_nodes = $7,
			current_round = $8,
			total_rounds = $9,
			signature = $10,
			completed_at = $11,
			duration_ms = $12
		WHERE session_id = $1
	`

	var completedAt interface{}
	if session.CompletedAt != nil {
		completedAt = *session.CompletedAt
	}

	_, err = s.db.ExecContext(ctx, query,
		session.SessionID, session.KeyID, session.Protocol, session.Status,
		session.Threshold, session.TotalNodes, participatingNodesJSON,
		session.CurrentRound, session.TotalRounds, session.Signature,
		completedAt, session.DurationMs,
	)
	if err != nil {
		return errors.Wrap(err, "failed to update signing session")
	}

	return nil
}

// GetSigningPolicy 获取签名策略
func (s *PostgreSQLStore) GetSigningPolicy(ctx context.Context, keyID string) (*SigningPolicy, error) {
	query := `
		SELECT wallet_id, policy_type, min_signatures, created_at, updated_at
		FROM signing_policies
		WHERE wallet_id = $1
	`

	var policy SigningPolicy
	err := s.db.QueryRowContext(ctx, query, keyID).Scan(
		&policy.WalletID, &policy.PolicyType, &policy.MinSignatures,
		&policy.CreatedAt, &policy.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("policy not found")
		}
		return nil, errors.Wrap(err, "failed to get signing policy")
	}

	return &policy, nil
}

// SaveSigningPolicy 保存签名策略
func (s *PostgreSQLStore) SaveSigningPolicy(ctx context.Context, policy *SigningPolicy) error {
	query := `
		INSERT INTO signing_policies (wallet_id, policy_type, min_signatures, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (wallet_id) DO UPDATE SET
			policy_type = EXCLUDED.policy_type,
			min_signatures = EXCLUDED.min_signatures,
			updated_at = EXCLUDED.updated_at
	`

	_, err := s.db.ExecContext(ctx, query,
		policy.WalletID, policy.PolicyType, policy.MinSignatures,
		policy.CreatedAt, policy.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, "failed to save signing policy")
	}

	return nil
}
