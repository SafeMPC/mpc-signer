package key

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// DKGService 分布式密钥生成服务
type DKGService struct {
	metadataStore   storage.MetadataStore
	keyShareStorage storage.KeyShareStorage
	protocolEngine  protocol.Engine
	nodeManager     *node.Manager
	nodeDiscovery   *node.Discovery
}

// NewDKGService 创建DKG服务
func NewDKGService(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
) *DKGService {
	return &DKGService{
		metadataStore:   metadataStore,
		keyShareStorage: keyShareStorage,
		protocolEngine:  protocolEngine,
		nodeManager:     nodeManager,
		nodeDiscovery:   nodeDiscovery,
	}
}

// ExecuteDKG 执行分布式密钥生成
func (s *DKGService) ExecuteDKG(ctx context.Context, keyID string, req *CreateKeyRequest) (*protocol.KeyGenResponse, error) {
	log.Error().
		Str("key_id", keyID).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Msg("ExecuteDKG: Starting DKG execution")

	// 1. 从DKG会话中获取参与节点列表（DKG会话使用keyID作为sessionID）
	session, err := s.metadataStore.GetSigningSession(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get DKG session")
	}

	// 2. 使用会话中的参与节点列表
	nodeIDs := session.ParticipatingNodes
	if len(nodeIDs) == 0 {
		return nil, errors.New("no participating nodes in DKG session")
	}

	log.Error().
		Str("key_id", keyID).
		Strs("node_ids", nodeIDs).
		Int("node_count", len(nodeIDs)).
		Msg("ExecuteDKG: Retrieved participating nodes from session")

	if len(nodeIDs) < req.Threshold {
		return nil, errors.Errorf("insufficient participating nodes: need at least %d, have %d", req.Threshold, len(nodeIDs))
	}

	// 3. 准备DKG请求
	dkgReq := &protocol.KeyGenRequest{
		KeyID:      keyID,
		Algorithm:  req.Algorithm,
		Curve:      req.Curve,
		Threshold:  req.Threshold,
		TotalNodes: req.TotalNodes,
		NodeIDs:    nodeIDs,
	}

	log.Error().
		Str("key_id", keyID).
		Msg("ExecuteDKG: Calling protocolEngine.GenerateKeyShare")

	// 4. 执行DKG协议
	dkgResp, err := s.protocolEngine.GenerateKeyShare(ctx, dkgReq)
	if err != nil {
		log.Error().Err(err).Str("key_id", keyID).Msg("ExecuteDKG: GenerateKeyShare failed")
		return nil, errors.Wrap(err, "failed to execute DKG protocol")
	}

	log.Error().
		Str("key_id", keyID).
		Int("key_share_count", len(dkgResp.KeyShares)).
		Str("public_key", dkgResp.PublicKey.Hex).
		Msg("ExecuteDKG: GenerateKeyShare completed successfully")

	// 5. 验证生成的密钥分片
	// 注意：在tss-lib架构中，每个节点只返回自己的KeyShare
	// 所以KeyShares的数量应该是1（当前节点），而不是TotalNodes
	if len(dkgResp.KeyShares) == 0 {
		return nil, errors.New("no key shares generated")
	}

	// 6. 验证公钥
	if dkgResp.PublicKey == nil || dkgResp.PublicKey.Hex == "" {
		return nil, errors.New("invalid public key from DKG")
	}

	return dkgResp, nil
}

// DistributeKeyShares 分发密钥分片到各个节点
func (s *DKGService) DistributeKeyShares(ctx context.Context, keyID string, keyShares map[string]*protocol.KeyShare) error {
	// 加密并分发密钥分片到各个节点
	for nodeID, share := range keyShares {
		// 存储密钥分片（内部会加密）
		if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, nodeID, share.Share); err != nil {
			return errors.Wrapf(err, "failed to store key share for node %s", nodeID)
		}
	}

	return nil
}

// RecoverKeyShare 恢复密钥分片（阈值恢复）
func (s *DKGService) RecoverKeyShare(ctx context.Context, keyID string, nodeIDs []string, threshold int) (*protocol.KeyShare, error) {
	// 收集阈值数量的密钥分片
	shares := make([][]byte, 0, threshold)
	indices := make([]int, 0, threshold)

	for i, nodeID := range nodeIDs {
		if i >= threshold {
			break
		}

		share, err := s.keyShareStorage.GetKeyShare(ctx, keyID, nodeID)
		if err != nil {
			continue // 跳过无法获取的分片
		}

		shares = append(shares, share)
		indices = append(indices, i+1) // 索引从1开始
	}

	if len(shares) < threshold {
		return nil, errors.Errorf("insufficient shares for recovery: need %d, have %d", threshold, len(shares))
	}

	// TODO: 使用Shamir秘密共享恢复完整密钥
	// 注意：这仅用于恢复场景，恢复后应立即重新生成分片

	return nil, errors.New("key share recovery not yet implemented - requires Shamir secret sharing")
}

// ValidateKeyShares 验证密钥分片一致性
func (s *DKGService) ValidateKeyShares(ctx context.Context, keyID string, publicKey *protocol.PublicKey) error {
	// TODO: 验证所有节点的密钥分片是否与公钥一致
	// 这需要实现Shamir秘密共享的验证逻辑

	return nil
}

// RotateKey 密钥轮换
func (s *DKGService) RotateKey(ctx context.Context, keyID string) error {
	// TODO: 实现密钥轮换协议
	// 1. 获取当前密钥信息
	// 2. 执行密钥轮换DKG
	// 3. 生成新的密钥分片
	// 4. 更新密钥元数据

	return errors.New("key rotation not yet implemented")
}
