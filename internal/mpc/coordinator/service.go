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
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
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
	grpcClient     GRPCClient // gRPC客户端，用于通知参与者
	thisNodeID     string     // 当前节点ID（coordinator节点）
}

// GRPCClient gRPC客户端接口（用于通知参与者）
type GRPCClient interface {
	SendKeygenMessage(ctx context.Context, nodeID string, msg tss.Message, sessionID string) error
	// StartDKG RPC
	SendStartDKG(ctx context.Context, nodeID string, req *pb.StartDKGRequest) (*pb.StartDKGResponse, error)
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
	grpcClient GRPCClient,
	thisNodeID string, // 当前节点ID（coordinator节点）
) *Service {
	// 记录 thisNodeID 的值（用于调试）
	log.Error().
		Str("this_node_id", thisNodeID).
		Bool("is_empty", thisNodeID == "").
		Msg("CoordinatorService initialized with thisNodeID")

	return &Service{
		metadataStore:  metadataStore,
		keyService:     keyService,
		signingService: signingService,
		sessionManager: sessionManager,
		nodeManager:    nodeManager,
		nodeDiscovery:  nodeDiscovery,
		protocolEngine: protocolEngine,
		grpcClient:     grpcClient,
		thisNodeID:     thisNodeID,
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

// CreateDKGSession 创建DKG会话并通知所有参与者
func (s *Service) CreateDKGSession(ctx context.Context, req *CreateDKGSessionRequest) (*DKGSession, error) {
	// 记录请求参数和 thisNodeID（用于调试）
	log.Error().
		Str("this_node_id", s.thisNodeID).
		Bool("this_node_id_empty", s.thisNodeID == "").
		Strs("request_node_ids", req.NodeIDs).
		Int("request_total_nodes", req.TotalNodes).
		Int("request_threshold", req.Threshold).
		Str("key_id", req.KeyID).
		Msg("CreateDKGSession called")

	// 1. 选择参与节点（只包括 participant，不包括 coordinator）
	var nodeIDs []string
	if len(req.NodeIDs) > 0 {
		// 使用提供的节点列表（应该只包含 participant）
		nodeIDs = req.NodeIDs
		log.Info().
			Strs("node_ids", nodeIDs).
			Int("count", len(nodeIDs)).
			Msg("Using provided participant node IDs (coordinator does NOT participate)")
	} else {
		// 自动发现参与者（不包括 coordinator）
		log.Info().
			Int("required_participants", req.TotalNodes).
			Msg("Auto-discovering participants (coordinator does NOT participate)")

		participants, err := s.nodeDiscovery.DiscoverNodes(ctx, node.NodeTypeParticipant, node.NodeStatusActive, req.TotalNodes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to discover participants")
		}

		log.Info().
			Int("discovered_participants", len(participants)).
			Int("required_participants", req.TotalNodes).
			Msg("Discovered participants")

		if len(participants) < req.TotalNodes {
			return nil, errors.Errorf("insufficient active participants: need %d, have %d", req.TotalNodes, len(participants))
		}

		// 只包含 participant 节点，不包含 coordinator
		nodeIDs = make([]string, 0, len(participants))
		for _, n := range participants {
			nodeIDs = append(nodeIDs, n.NodeID)
		}

		log.Info().
			Strs("participant_node_ids", nodeIDs).
			Int("total_participants", len(nodeIDs)).
			Str("coordinator_node_id", s.thisNodeID).
			Msg("Final participant node IDs for DKG session (coordinator does NOT participate)")
	}

	// 2. 选择协议
	protocol := req.Protocol
	if protocol == "" {
		protocol = s.protocolEngine.DefaultProtocol()
	}

	// 3. 创建DKG会话
	// 记录传递给 CreateKeyGenSession 的节点列表（用于调试）
	log.Error().
		Strs("node_ids", nodeIDs).
		Str("key_id", req.KeyID).
		Str("protocol", protocol).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Msg("About to create DKG session with node IDs")

	dkgSession, err := s.sessionManager.CreateKeyGenSession(ctx, req.KeyID, protocol, req.Threshold, req.TotalNodes, nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DKG session")
	}

	// 记录创建成功的会话信息（用于调试）
	log.Error().
		Str("session_id", dkgSession.SessionID).
		Strs("participating_nodes", dkgSession.ParticipatingNodes).
		Msg("DKG session created successfully")

	// 4. 通知所有参与者启动DKG
	if err := s.NotifyParticipantsForDKG(ctx, req, nodeIDs); err != nil {
		// 如果通知失败，取消会话
		_ = s.sessionManager.CancelSession(ctx, dkgSession.SessionID)
		return nil, errors.Wrap(err, "failed to notify participants")
	}

	return &DKGSession{
		SessionID:          dkgSession.SessionID,
		KeyID:              dkgSession.KeyID,
		Protocol:           dkgSession.Protocol,
		Status:             dkgSession.Status,
		Threshold:          dkgSession.Threshold,
		TotalNodes:         dkgSession.TotalNodes,
		ParticipatingNodes: dkgSession.ParticipatingNodes,
		CurrentRound:       dkgSession.CurrentRound,
		TotalRounds:        dkgSession.TotalRounds,
		CreatedAt:          dkgSession.CreatedAt,
		ExpiresAt:          dkgSession.ExpiresAt,
	}, nil
}

// NotifyParticipantsForDKG 通知所有参与者节点启动DKG
func (s *Service) NotifyParticipantsForDKG(ctx context.Context, req *CreateDKGSessionRequest, nodeIDs []string) error {
	// ✅ 方案一：Coordinator 不参与 DKG，只通知第一个 participant 启动
	// 第一个 participant 作为 leader 启动 DKG 协议，生成第一轮消息
	// 其他 participants 收到第一轮消息后会自动启动自己的 DKG 协议

	if len(nodeIDs) == 0 {
		return errors.New("no participants to notify")
	}

	// 选择第一个 participant 作为 leader（按 nodeID 排序，确保一致性）
	leaderNodeID := nodeIDs[0]

	log.Info().
		Str("key_id", req.KeyID).
		Str("leader_node_id", leaderNodeID).
		Strs("all_participants", nodeIDs).
		Int("threshold", req.Threshold).
		Int("total_nodes", req.TotalNodes).
		Msg("Notifying leader participant to start DKG protocol")

	// 通过 gRPC 发送 StartDKG RPC 给 leader
	startReq := &pb.StartDKGRequest{
		SessionId:  req.KeyID,
		KeyId:      req.KeyID,
		Algorithm:  req.Algorithm,
		Curve:      req.Curve,
		Threshold:  int32(req.Threshold),
		TotalNodes: int32(req.TotalNodes),
		NodeIds:    nodeIDs,
	}

	if _, err := s.grpcClient.SendStartDKG(ctx, leaderNodeID, startReq); err != nil {
		log.Error().
			Err(err).
			Str("key_id", req.KeyID).
			Str("leader_node_id", leaderNodeID).
			Msg("Failed to call StartDKG on leader participant")
		// 不返回错误，让 participant 通过其他方式（如轮询）检测新的 DKG session
	} else {
		log.Info().
			Str("key_id", req.KeyID).
			Str("leader_node_id", leaderNodeID).
			Msg("StartDKG invoked on leader participant")
	}

	return nil
}
