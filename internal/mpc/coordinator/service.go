package coordinator

import (
	"context"
	"encoding/hex"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/signing"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Service Coordinator服务
type Service struct {
	metadataStore  storage.MetadataStore
	keyService     *key.Service
	signingService *signing.Service
	sessionManager *session.Manager
	nodeManager    *node.Manager
	nodeDiscovery  *node.Discovery
	protocolEngine protocol.Engine
}

// NewService 创建Coordinator服务
func NewService(
	metadataStore storage.MetadataStore,
	keyService *key.Service,
	signingService *signing.Service,
	sessionManager *session.Manager,
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
	protocolEngine protocol.Engine,
) *Service {
	return &Service{
		metadataStore:  metadataStore,
		keyService:     keyService,
		signingService: signingService,
		sessionManager: sessionManager,
		nodeManager:    nodeManager,
		nodeDiscovery:  nodeDiscovery,
		protocolEngine: protocolEngine,
	}
}

// CreateSigningSession 创建签名会话
func (s *Service) CreateSigningSession(ctx context.Context, req *CreateSessionRequest) (*SigningSession, error) {
	// 获取密钥信息
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key")
	}

	// 选择协议
	protocol := req.Protocol
	if protocol == "" {
		protocol = s.protocolEngine.DefaultProtocol()
	}

	// 创建会话
	session, err := s.sessionManager.CreateSession(ctx, req.KeyID, protocol, keyMetadata.Threshold, keyMetadata.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	return &SigningSession{
		SessionID:          session.SessionID,
		KeyID:              session.KeyID,
		Protocol:           session.Protocol,
		Status:             session.Status,
		Threshold:          session.Threshold,
		TotalNodes:         session.TotalNodes,
		ParticipatingNodes: session.ParticipatingNodes,
		CurrentRound:       session.CurrentRound,
		TotalRounds:        session.TotalRounds,
		Signature:          session.Signature,
		CreatedAt:          session.CreatedAt,
		CompletedAt:        session.CompletedAt,
		DurationMs:         session.DurationMs,
		ExpiresAt:          session.ExpiresAt,
	}, nil
}

// JoinSigningSession 节点加入签名会话
func (s *Service) JoinSigningSession(ctx context.Context, sessionID string, nodeID string) error {
	if err := s.sessionManager.JoinSession(ctx, sessionID, nodeID); err != nil {
		return errors.Wrap(err, "failed to join session")
	}
	return nil
}

// GetSigningSession 获取签名会话
func (s *Service) GetSigningSession(ctx context.Context, sessionID string) (*SigningSession, error) {
	session, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get session")
	}

	return &SigningSession{
		SessionID:          session.SessionID,
		KeyID:              session.KeyID,
		Protocol:           session.Protocol,
		Status:             session.Status,
		Threshold:          session.Threshold,
		TotalNodes:         session.TotalNodes,
		ParticipatingNodes: session.ParticipatingNodes,
		CurrentRound:       session.CurrentRound,
		TotalRounds:        session.TotalRounds,
		Signature:          session.Signature,
		CreatedAt:          session.CreatedAt,
		CompletedAt:        session.CompletedAt,
		DurationMs:         session.DurationMs,
		ExpiresAt:          session.ExpiresAt,
	}, nil
}

// AggregateSignatures 聚合签名分片
// Deprecated: 在tss-lib分布式签名方案中，签名聚合由tss-lib自动完成
// 每个节点都能得到完整签名，不需要Coordinator聚合
// 此方法保留用于向后兼容，但不应被使用
func (s *Service) AggregateSignatures(ctx context.Context, sessionID string) (*Signature, error) {
	// 在tss-lib分布式签名方案中，签名聚合由tss-lib自动完成
	// 每个节点都能得到完整签名，不需要Coordinator聚合
	// 如果需要获取签名，应该从会话中获取，而不是聚合
	session, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get session")
	}

	if session.Signature == "" {
		return nil, errors.New("signature not yet available in session")
	}

	// 解析签名
	sigBytes, err := hex.DecodeString(session.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode signature")
	}

	// 简化的签名结构（实际应该根据协议类型解析）
	return &Signature{
		Bytes: sigBytes,
		Hex:   session.Signature,
	}, nil
}
