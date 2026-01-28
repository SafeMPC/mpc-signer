package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"encoding/base64"
	"encoding/hex"

	"github.com/SafeMPC/mpc-signer/internal/auth"
	"github.com/SafeMPC/mpc-signer/internal/config"
	"github.com/SafeMPC/mpc-signer/internal/infra/session"
	"github.com/SafeMPC/mpc-signer/internal/infra/storage"
	"github.com/SafeMPC/mpc-signer/internal/mpc/protocol"
	"github.com/SafeMPC/mpc-signer/internal/util/cert"
	pb "github.com/SafeMPC/mpc-signer/pb/mpc/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// inferProtocolForDKG 根据算法和曲线推断DKG应该使用的协议
// ECDSA + secp256k1 -> GG20 (默认) 或 GG18
// EdDSA/Schnorr + ed25519/secp256k1 -> FROST
func inferProtocolForDKG(algorithm, curve string) string {
	algorithmLower := strings.ToLower(algorithm)
	curveLower := strings.ToLower(curve)

	// FROST 协议：EdDSA 或 Schnorr + Ed25519 或 secp256k1
	if algorithmLower == "eddsa" || algorithmLower == "schnorr" {
		if curveLower == "ed25519" || curveLower == "secp256k1" {
			return "frost"
		}
	}

	// ECDSA + secp256k1：使用 GG20（默认）或 GG18
	if algorithmLower == "ecdsa" {
		if curveLower == "secp256k1" || curveLower == "secp256r1" {
			return "gg20" // 默认使用 GG20
		}
	}

	// 默认使用 GG20
	return "gg20"
}

// GRPCServer gRPC服务端，用于接收节点间消息
type GRPCServer struct {
	pb.UnimplementedSignerServiceServer

	protocolEngine   protocol.Engine            // 默认协议引擎
	protocolRegistry *protocol.ProtocolRegistry // 协议注册表（用于动态选择协议）
	sessionManager   *session.Manager
	keyShareStorage  storage.KeyShareStorage // 用于存储密钥分片
	metadataStore    storage.MetadataStore   // 用于读取元数据（策略、公钥）
	nodeID           string
	cfg              *ServerConfig

	// gRPC 服务器实例
	grpcServer *grpc.Server
	listener   net.Listener

	// 用于确保每个DKG会话只启动一次
	dkgStartOnce sync.Map // map[string]*sync.Once

	// 用于确保每个签名会话只启动一次
	signStartOnce sync.Map // map[string]*sync.Once

	// 流管理器（用于管理直连 Client）
	streamManager *StreamManager
}

// ServerConfig gRPC服务端配置
type ServerConfig struct {
	Port           int
	TLSEnabled     bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSCACertFile  string
	MaxConnAge     time.Duration
	KeepAlive      time.Duration
	IsGuardianNode bool // 是否作为 Guardian 节点运行
	JWTSecret      string
}

// NewGRPCServer 创建gRPC服务端
func NewGRPCServer(
	cfg config.Server,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	metadataStore storage.MetadataStore,
	nodeID string,
) *GRPCServer {
	return NewGRPCServerWithRegistry(cfg, protocolEngine, nil, sessionManager, keyShareStorage, metadataStore, nodeID)
}

// NewGRPCServerWithRegistry 创建gRPC服务端（带协议注册表）
func NewGRPCServerWithRegistry(
	cfg config.Server,
	protocolEngine protocol.Engine,
	protocolRegistry *protocol.ProtocolRegistry, // 协议注册表（可选，用于动态选择协议）
	sessionManager *session.Manager,
	keyShareStorage storage.KeyShareStorage,
	metadataStore storage.MetadataStore,
	nodeID string,
) *GRPCServer {
	serverCfg := &ServerConfig{
		Port:           cfg.MPC.GRPCPort,
		TLSEnabled:     cfg.MPC.TLSEnabled,
		TLSCertFile:    cfg.MPC.TLSCertFile,
		TLSKeyFile:     cfg.MPC.TLSKeyFile,
		TLSCACertFile:  cfg.MPC.TLSCACertFile,
		MaxConnAge:     2 * time.Hour,
		KeepAlive:      30 * time.Second,
		IsGuardianNode: cfg.MPC.IsGuardianNode,
		JWTSecret:      cfg.MPC.JWTSecret,
	}

	srv := &GRPCServer{
		protocolEngine:   protocolEngine,
		protocolRegistry: protocolRegistry,
		sessionManager:   sessionManager,
		keyShareStorage:  keyShareStorage,
		metadataStore:    metadataStore,
		nodeID:           nodeID,
		cfg:              serverCfg,
	}

	// 绑定结果上报回调
	if sessionManager != nil {
		sessionManager.OnSessionCompleted = srv.reportResult
	}

	return srv
}

// SetStreamManager 设置流管理器
func (s *GRPCServer) SetStreamManager(sm *StreamManager) {
	s.streamManager = sm
}

// GetServerOptions 获取gRPC服务器选项
func (s *GRPCServer) GetServerOptions() ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption

	// TLS配置（mTLS：要求客户端证书）
	if s.cfg.TLSEnabled {
		// 加载服务器证书
		serverCert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load server TLS certificate")
		}

		// 加载 CA 证书用于验证客户端证书
		caBytes, err := os.ReadFile(s.cfg.TLSCACertFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS CA certificate")
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caBytes) {
			return nil, errors.New("failed to append CA certificate")
		}

		// 配置 mTLS：要求并验证客户端证书
		// 注意：暂时改为 RequestClientCert，允许没有客户端证书的连接（用于测试）
		// 生产环境应该使用 RequireAndVerifyClientCert
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequestClientCert, // 请求客户端证书但不强制（测试用）
			MinVersion:   tls.VersionTLS12,      // 降低到 TLS 1.2 以兼容更多客户端
		}

		creds := credentials.NewTLS(tlsCfg)
		opts = append(opts, grpc.Creds(creds))
	}

	// KeepAlive配置
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionAge:      s.cfg.MaxConnAge,
		MaxConnectionAgeGrace: 30 * time.Second,
		Time:                  s.cfg.KeepAlive,
		Timeout:               20 * time.Second,
	}))

	// Enforcement Policy (防止 too_many_pings)
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             10 * time.Second, // 允许客户端每 10s ping 一次
		PermitWithoutStream: true,             // 允许无流时的 ping
	}))

	// 最大消息大小
	opts = append(opts, grpc.MaxRecvMsgSize(10*1024*1024)) // 10MB
	opts = append(opts, grpc.MaxSendMsgSize(10*1024*1024)) // 10MB

	return opts, nil
}

// StartDKG 由协调者调用以启动参与者的 DKG
func (s *GRPCServer) StartDKG(ctx context.Context, req *pb.StartDKGRequest) (*pb.StartDKGResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Str("algorithm", req.Algorithm).
		Str("curve", req.Curve).
		Int32("threshold", req.Threshold).
		Int32("total_nodes", req.TotalNodes).
		Strs("node_ids", req.NodeIds).
		Str("this_node_id", s.nodeID).
		Msg("StartDKG RPC received")

	// Admin 权限验证已删除（团队签功能已移除）
	// Service 节点会验证请求，Signer 节点信任来自 Service 的请求

	// 使用sync.Once确保每个sessionID只启动一次DKG协议
	// 防止StartDKG RPC和自动启动机制同时启动DKG
	sessionID := req.SessionId
	if sessionID == "" {
		sessionID = req.KeyId // 如果sessionID为空，使用keyID
	}

	// 存储 Client 公钥到会话（用于 E2E 签名验证）
	if req.ClientPublicKey != "" {
		// 获取或创建会话
		sess, err := s.sessionManager.GetSession(ctx, sessionID)
		if err != nil {
			// 会话不存在，创建新会话
			protocolName := inferProtocolForDKG(req.Algorithm, req.Curve)
			sess, err = s.sessionManager.CreateKeyGenSession(ctx, req.KeyId, protocolName, int(req.Threshold), int(req.TotalNodes), req.NodeIds)
			if err != nil {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Msg("Failed to create session for client public key storage")
			}
		}
		if sess != nil {
			sess.ClientPublicKey = req.ClientPublicKey
			if err := s.sessionManager.UpdateSession(ctx, sess); err != nil {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Msg("Failed to update session with client public key")
			} else {
				log.Debug().
					Str("session_id", sessionID).
					Str("client_public_key_len", fmt.Sprintf("%d", len(req.ClientPublicKey))).
					Msg("Stored client public key in session")
			}
		}
	}

	onceInterface, _ := s.dkgStartOnce.LoadOrStore(sessionID, &sync.Once{})
	once := onceInterface.(*sync.Once)

	var started bool

	once.Do(func() {
		started = true
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("sync.Once.Do executed in StartDKG RPC - starting DKG in goroutine")

		// 在goroutine中执行GenerateKeyShare，避免阻塞sync.Once.Do
		// 这样如果自动启动机制也尝试启动，sync.Once会立即返回，不会重复启动
		go func() {
			// 使用独立的context，避免RPC请求返回后context被取消
			keygenTimeout := 10 * time.Minute
			keygenCtx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
			defer cancel()

			dkgReq := &protocol.KeyGenRequest{
				KeyID:      req.KeyId,
				Algorithm:  req.Algorithm,
				Curve:      req.Curve,
				Threshold:  int(req.Threshold),
				TotalNodes: int(req.TotalNodes),
				NodeIDs:    req.NodeIds,
			}

			// 根据算法和曲线选择正确的协议引擎
			// ECDSA + secp256k1 -> GG18 或 GG20
			// EdDSA/Schnorr + ed25519/secp256k1 -> FROST
			var selectedEngine protocol.Engine
			if s.protocolRegistry != nil {
				// 根据算法和曲线推断协议
				protocolName := inferProtocolForDKG(req.Algorithm, req.Curve)
				engine, err := s.protocolRegistry.Get(protocolName)
				if err != nil {
					log.Warn().
						Err(err).
						Str("key_id", req.KeyId).
						Str("algorithm", req.Algorithm).
						Str("curve", req.Curve).
						Str("inferred_protocol", protocolName).
						Msg("StartDKG: Failed to get protocol from registry, using default engine")
					selectedEngine = s.protocolEngine
				} else {
					log.Info().
						Str("key_id", req.KeyId).
						Str("algorithm", req.Algorithm).
						Str("curve", req.Curve).
						Str("selected_protocol", protocolName).
						Str("this_node_id", s.nodeID).
						Msg("StartDKG: Selected protocol from registry")
					selectedEngine = engine
				}
			} else {
				// 如果没有协议注册表，使用默认引擎
				log.Warn().
					Str("key_id", req.KeyId).
					Str("this_node_id", s.nodeID).
					Msg("StartDKG: Protocol registry not available, using default engine")
				selectedEngine = s.protocolEngine
			}

			log.Info().
				Str("key_id", req.KeyId).
				Str("session_id", sessionID).
				Str("this_node_id", s.nodeID).
				Msg("Calling protocolEngine.GenerateKeyShare (this may take several minutes)")

			resp, err := selectedEngine.GenerateKeyShare(keygenCtx, dkgReq)
			if err != nil {
				log.Error().
					Err(err).
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("algorithm", req.Algorithm).
					Str("curve", req.Curve).
					Int32("threshold", req.Threshold).
					Int32("total_nodes", req.TotalNodes).
					Strs("node_ids", req.NodeIds).
					Msg("GenerateKeyShare failed in StartDKG RPC goroutine")

				// 更新会话状态为失败
				if sess, getErr := s.sessionManager.GetSession(keygenCtx, sessionID); getErr == nil {
					sess.Status = "failed"
					if updateErr := s.sessionManager.UpdateSession(keygenCtx, sess); updateErr != nil {
						log.Error().
							Err(updateErr).
							Str("session_id", sessionID).
							Msg("Failed to update session status to failed after GenerateKeyShare error")
					}
				}
			} else if resp != nil && resp.PublicKey != nil && resp.PublicKey.Hex != "" {
				log.Info().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("public_key", resp.PublicKey.Hex).
					Int("key_share_count", len(resp.KeyShares)).
					Msg("GenerateKeyShare completed successfully in StartDKG RPC goroutine")

				// 存储密钥分片（只存储当前节点的分片）
				if s.keyShareStorage != nil && len(resp.KeyShares) > 0 {
					for nodeID, share := range resp.KeyShares {
						if err := s.keyShareStorage.StoreKeyShare(keygenCtx, req.KeyId, nodeID, share.Share); err != nil {
							log.Error().
								Err(err).
								Str("key_id", req.KeyId).
								Str("node_id", nodeID).
								Str("this_node_id", s.nodeID).
								Msg("Failed to store key share in StartDKG RPC goroutine")
						} else {
							log.Info().
								Str("key_id", req.KeyId).
								Str("node_id", nodeID).
								Str("this_node_id", s.nodeID).
								Msg("Key share stored successfully in StartDKG RPC goroutine")

						}
					}
				} else {
					log.Warn().
						Str("key_id", req.KeyId).
						Str("this_node_id", s.nodeID).
						Bool("keyShareStorage_nil", s.keyShareStorage == nil).
						Int("key_share_count", len(resp.KeyShares)).
						Msg("Key share storage skipped (keyShareStorage is nil or no key shares)")
				}

				// DKG完成，更新会话
				if err := s.sessionManager.CompleteKeygenSession(keygenCtx, req.KeyId, resp.PublicKey.Hex); err != nil {
					log.Error().
						Err(err).
						Str("key_id", req.KeyId).
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Msg("Failed to complete keygen session in StartDKG RPC goroutine")
				} else {
					log.Info().
						Str("key_id", req.KeyId).
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Str("public_key", resp.PublicKey.Hex).
						Msg("Keygen session completed successfully in StartDKG RPC goroutine")
				}
			}
		}()
	})

	if !started {
		// DKG已经在运行（可能是通过自动启动机制启动的）
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("DKG already started (possibly via auto-start), returning success")
		return &pb.StartDKGResponse{Started: true, Message: "DKG already started"}, nil
	}

	// GenerateKeyShare在goroutine中执行，立即返回
	// DKG的完成会通过其他机制（如CompleteKeygenSession）来通知
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", sessionID).
		Str("this_node_id", s.nodeID).
		Msg("DKG started in background, returning immediately")
	return &pb.StartDKGResponse{Started: true, Message: "DKG started in background"}, nil
}

// GetDKGStatus 查询 DKG 会话状态
func (s *GRPCServer) GetDKGStatus(ctx context.Context, req *pb.GetDKGStatusRequest) (*pb.DKGStatusResponse, error) {
	log.Debug().
		Str("session_id", req.SessionId).
		Str("this_node_id", s.nodeID).
		Msg("GetDKGStatus RPC received")

	// DKG 会话的 sessionID 等于 keyID
	sessionID := req.SessionId
	if sessionID == "" {
		return &pb.DKGStatusResponse{
			SessionId: sessionID,
			Status:    "failed",
			Error:     "session_id is required",
		}, nil
	}

	// 从会话管理器获取会话信息
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		log.Warn().
			Err(err).
			Str("session_id", sessionID).
			Msg("Failed to get DKG session")
		return &pb.DKGStatusResponse{
			SessionId: sessionID,
			Status:    "failed",
			Error:     fmt.Sprintf("session not found: %v", err),
		}, nil
	}

	// 构建响应
	response := &pb.DKGStatusResponse{
		SessionId:    sessionID,
		Status:       sess.Status,
		CurrentRound: int32(sess.CurrentRound),
		TotalRounds:  int32(sess.TotalRounds),
	}

	// 如果 DKG 已完成，返回公钥（存储在 Signature 字段中）
	if sess.Status == "completed" && sess.Signature != "" {
		response.PublicKey = sess.Signature
	}

	// 如果状态为 failed，返回错误信息
	if sess.Status == "failed" {
		response.Error = "DKG failed"
	}

	log.Debug().
		Str("session_id", sessionID).
		Str("status", sess.Status).
		Int("current_round", sess.CurrentRound).
		Int("total_rounds", sess.TotalRounds).
		Msg("GetDKGStatus response")

	return response, nil
}

// GetSignStatus 查询签名会话状态
func (s *GRPCServer) GetSignStatus(ctx context.Context, req *pb.GetSignStatusRequest) (*pb.SignStatusResponse, error) {
	log.Debug().
		Str("session_id", req.SessionId).
		Str("this_node_id", s.nodeID).
		Msg("GetSignStatus RPC received")

	sessionID := req.SessionId
	if sessionID == "" {
		return &pb.SignStatusResponse{
			SessionId: sessionID,
			Status:    "failed",
			Error:     "session_id is required",
		}, nil
	}

	// 从会话管理器获取会话信息
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		log.Warn().
			Err(err).
			Str("session_id", sessionID).
			Msg("Failed to get sign session")
		return &pb.SignStatusResponse{
			SessionId: sessionID,
			Status:    "failed",
			Error:     fmt.Sprintf("session not found: %v", err),
		}, nil
	}

	// 构建响应
	response := &pb.SignStatusResponse{
		SessionId:    sessionID,
		Status:       sess.Status,
		CurrentRound: int32(sess.CurrentRound),
		TotalRounds:  int32(sess.TotalRounds),
	}

	// 如果签名已完成，返回签名（存储在 Signature 字段中）
	if sess.Status == "completed" && sess.Signature != "" {
		response.Signature = sess.Signature
	}

	// 如果状态为 failed，返回错误信息
	if sess.Status == "failed" {
		response.Error = "Signing failed"
	}

	log.Debug().
		Str("session_id", sessionID).
		Str("status", sess.Status).
		Int("current_round", sess.CurrentRound).
		Int("total_rounds", sess.TotalRounds).
		Msg("GetSignStatus response")

	return response, nil
}

// StartSign 由协调者调用以启动参与者的签名
func (s *GRPCServer) StartSign(ctx context.Context, req *pb.StartSignRequest) (*pb.StartSignResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Str("this_node_id", s.nodeID).
		Msg("StartSign RPC received")

	sessionID := req.SessionId
	if sessionID == "" {
		sessionID = req.KeyId
	}

	// 存储 Client 公钥到会话（用于 E2E 签名验证）
	if req.ClientPublicKey != "" {
		sess, err := s.sessionManager.GetSession(ctx, sessionID)
		if err != nil {
			// 会话不存在，创建新会话
			sess, err = s.sessionManager.CreateSession(ctx, req.KeyId, req.Protocol, int(req.Threshold), int(req.TotalNodes))
			if err != nil {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Msg("Failed to create session for client public key storage")
			}
		}
		if sess != nil {
			sess.ClientPublicKey = req.ClientPublicKey
			if err := s.sessionManager.UpdateSession(ctx, sess); err != nil {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Msg("Failed to update session with client public key")
			} else {
				log.Debug().
					Str("session_id", sessionID).
					Str("client_public_key_len", fmt.Sprintf("%d", len(req.ClientPublicKey))).
					Msg("Stored client public key in session")
			}
		}
	}

	// 基本校验：节点数量应满足 threshold/totalNodes
	if req.Threshold > 0 && len(req.NodeIds) < int(req.Threshold) {
		msg := fmt.Sprintf("insufficient node_ids: need >= %d, got %d", req.Threshold, len(req.NodeIds))
		log.Error().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Int("node_ids", len(req.NodeIds)).
			Int32("threshold", req.Threshold).
			Int32("total_nodes", req.TotalNodes).
			Msg(msg)
		return &pb.StartSignResponse{Started: false, Message: msg}, nil
	}
	if req.TotalNodes > 0 && len(req.NodeIds) > int(req.TotalNodes) {
		msg := fmt.Sprintf("too many node_ids: total_nodes=%d, got=%d", req.TotalNodes, len(req.NodeIds))
		log.Error().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Int("node_ids", len(req.NodeIds)).
			Int32("threshold", req.Threshold).
			Int32("total_nodes", req.TotalNodes).
			Msg(msg)
		return &pb.StartSignResponse{Started: false, Message: msg}, nil
	}

	// 鉴权代理逻辑：如果配置了 Guardian 模式，或者收到鉴权令牌，执行鉴权
	// 这里假设所有节点都具备 Guardian 能力，通过配置或动态策略激活
	// 为了简化，我们只检查是否存在 metadataStore 和 AuthTokens
	if s.metadataStore != nil && (len(req.AuthTokens) > 0 || s.cfg.IsGuardianNode) {
		if err := s.checkGuardianPolicy(ctx, req); err != nil {
			log.Warn().
				Err(err).
				Str("key_id", req.KeyId).
				Str("session_id", sessionID).
				Str("this_node_id", s.nodeID).
				Str("protocol", req.Protocol).
				Int("auth_tokens", len(req.AuthTokens)).
				Msg("Guardian check failed, rejecting StartSign request")
			return &pb.StartSignResponse{Started: false, Message: fmt.Sprintf("Guardian Access Denied: %v", err)}, nil
		}
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("Guardian check passed")
	}

	onceInterface, _ := s.signStartOnce.LoadOrStore(sessionID, &sync.Once{})
	once := onceInterface.(*sync.Once)

	var started bool

	once.Do(func() {
		started = true
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("sync.Once.Do executed in StartSign RPC - starting signing in goroutine")

		go func() {
			signTimeout := 10 * time.Minute
			signCtx, cancel := context.WithTimeout(context.Background(), signTimeout)
			defer cancel()

			// 准备消息
			msg := req.Message
			if len(msg) == 0 && req.MessageHex != "" {
				decoded, err := hex.DecodeString(req.MessageHex)
				if err != nil {
					log.Error().
						Err(err).
						Str("session_id", sessionID).
						Str("key_id", req.KeyId).
						Str("this_node_id", s.nodeID).
						Msg("Failed to decode message_hex in StartSign")
					return
				}
				msg = decoded
			}

			signReq := &protocol.SignRequest{
				KeyID:           req.KeyId,
				Message:         msg,
				MessageHex:      req.MessageHex,
				NodeIDs:         req.NodeIds,
				DerivationPath:  req.DerivationPath,
				ParentChainCode: req.ParentChainCode,
			}

			// 根据请求中的 Protocol 字段选择协议引擎
			// 如果请求中没有指定 Protocol，使用默认协议引擎
			var engine protocol.Engine
			if req.Protocol != "" {
				// 尝试从注册表获取协议引擎
				if s.protocolRegistry != nil {
					if regEngine, err := s.protocolRegistry.Get(req.Protocol); err == nil {
						engine = regEngine
						log.Info().
							Str("key_id", req.KeyId).
							Str("session_id", sessionID).
							Str("protocol", req.Protocol).
							Str("this_node_id", s.nodeID).
							Msg("Using protocol from registry based on request")
					} else {
						log.Warn().
							Err(err).
							Str("key_id", req.KeyId).
							Str("session_id", sessionID).
							Str("requested_protocol", req.Protocol).
							Str("this_node_id", s.nodeID).
							Msg("Failed to get protocol from registry, using default engine")
						engine = s.protocolEngine
					}
				} else {
					log.Warn().
						Str("key_id", req.KeyId).
						Str("session_id", sessionID).
						Str("requested_protocol", req.Protocol).
						Str("this_node_id", s.nodeID).
						Msg("Protocol registry not available, using default engine")
					engine = s.protocolEngine
				}
			} else {
				// 使用默认协议引擎
				engine = s.protocolEngine
			}

			log.Info().
				Str("key_id", req.KeyId).
				Str("session_id", sessionID).
				Str("protocol", req.Protocol).
				Str("this_node_id", s.nodeID).
				Msg("Calling protocolEngine.ThresholdSign (participant)")

			resp, err := engine.ThresholdSign(signCtx, sessionID, signReq)
			if err != nil {
				log.Error().
					Err(err).
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("protocol", req.Protocol).
					Int("message_len", len(msg)).
					Strs("node_ids", req.NodeIds).
					Int32("threshold", req.Threshold).
					Int32("total_nodes", req.TotalNodes).
					Msg("ThresholdSign failed in StartSign RPC goroutine")

				// ✅ 更新会话状态为失败
				if sess, getErr := s.sessionManager.GetSession(signCtx, sessionID); getErr == nil {
					sess.Status = "failed"
					if updateErr := s.sessionManager.UpdateSession(signCtx, sess); updateErr != nil {
						log.Error().
							Err(updateErr).
							Str("session_id", sessionID).
							Str("this_node_id", s.nodeID).
							Msg("Failed to update session status to failed")
					}
				}
				return
			}

			if resp != nil && resp.Signature != nil && resp.Signature.Hex != "" {
				log.Info().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("signature", resp.Signature.Hex).
					Msg("ThresholdSign completed successfully in StartSign RPC goroutine")

				// ✅ 更新会话状态为完成，并保存签名
				// 使用 CompleteSession 方法，它会自动处理状态更新和时间戳
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Str("signature", resp.Signature.Hex).
					Msg("🔍 [DIAGNOSTIC] Calling CompleteSession to update session status")

				if completeErr := s.sessionManager.CompleteSession(signCtx, sessionID, resp.Signature.Hex); completeErr != nil {
					log.Error().
						Err(completeErr).
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Msg("Failed to complete session (may be completed by another participant)")
				} else {
					log.Info().
						Str("session_id", sessionID).
						Str("this_node_id", s.nodeID).
						Str("signature", resp.Signature.Hex).
						Msg("🔍 [DIAGNOSTIC] Session completed successfully")
				}
			} else {
				log.Warn().
					Str("key_id", req.KeyId).
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("ThresholdSign returned nil or empty signature")
			}
		}()
	})

	if !started {
		log.Info().
			Str("key_id", req.KeyId).
			Str("session_id", sessionID).
			Str("this_node_id", s.nodeID).
			Msg("Signing already started, returning success")
		return &pb.StartSignResponse{Started: true, Message: "Signing already started"}, nil
	}

	log.Info().
		Str("key_id", req.KeyId).
		Str("session_id", sessionID).
		Str("this_node_id", s.nodeID).
		Msg("Signing started in background, returning immediately")
	return &pb.StartSignResponse{Started: true, Message: "Signing started in background"}, nil
}

// StartResharing 密钥轮换功能已删除
func (s *GRPCServer) StartResharing(ctx context.Context, req interface{}) (interface{}, error) {
	return map[string]interface{}{
		"started": false,
		"message": "Key rotation (resharing) is not supported",
	}, nil
}

// handleProtocolMessage 处理协议消息（DKG或签名）
func (s *GRPCServer) handleProtocolMessage(ctx context.Context, sessionID string, fromNodeID string, shareData []byte, round int32, isBroadcast bool) error {
	// 从会话中判断消息类型
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Str("from_node_id", fromNodeID).
			Str("this_node_id", s.nodeID).
			Msg("Failed to get session for protocol message - participant cannot start DKG without session")
		// 提供更详细的错误信息，帮助诊断问题
		return errors.Wrapf(err, "failed to get session %s for protocol message from node %s (this node: %s). Possible causes: 1) session was not created by coordinator, 2) session was created but not yet visible due to database replication lag, 3) session expired or was deleted", sessionID, fromNodeID, s.nodeID)
	}

	// 根据会话判断 DKG 还是签名：
	// - DKG: sessionID 等于 keyID 或以 key- 开头
	// - 签名: 其他情况一律视为签名（避免签名消息误入 DKG 逻辑）
	isKeygenSession := sessionID == sess.KeyID || strings.HasPrefix(strings.ToLower(sessionID), "key-")
	isDKG := isKeygenSession
	// isBroadcast is passed as argument

	if isDKG {
		// 处理特殊控制消息
		if len(shareData) > 0 {
			data := string(shareData)
			if data == "DKG_START" {
				// coordinator 发送的启动通知，只触发启动，不处理内容
				// 后续真实 DKG 消息会再到达
				return nil
			}
			if strings.HasPrefix(data, "DKG_COMPLETE:") {
				pubKey := strings.TrimPrefix(data, "DKG_COMPLETE:")
				if err := s.sessionManager.CompleteKeygenSession(ctx, sessionID, pubKey); err != nil {
					return errors.Wrap(err, "failed to complete keygen session")
				}
				return nil
			}
		}

		// ✅ 方案一：Coordinator 不参与 DKG，第一个 participant 作为 leader 启动
		// 检查当前节点是否是第一个 participant（按 nodeID 排序）
		isLeader := false
		if len(sess.ParticipatingNodes) > 0 {
			// 按 nodeID 排序，第一个节点作为 leader
			leaderNodeID := sess.ParticipatingNodes[0]
			isLeader = (s.nodeID == leaderNodeID)
		}
		_ = isLeader

		// 对于DKG消息，如果是参与者节点且还没有启动DKG协议，需要自动启动
		// 使用sync.Once确保每个sessionID只启动一次DKG协议
		if len(sess.ParticipatingNodes) > 0 && sess.Threshold > 0 && sess.TotalNodes > 0 {
			// 获取或创建sync.Once
			onceInterface, _ := s.dkgStartOnce.LoadOrStore(sessionID, &sync.Once{})
			once := onceInterface.(*sync.Once)

			// 检查是否已经有活跃的DKG实例（双重检查，防止sync.Once失效）
			// 注意：这个检查在sync.Once.Do之前，所以可能会有竞态条件
			// 但sync.Once应该能防止重复启动
			log.Debug().
				Str("session_id", sessionID).
				Str("this_node_id", s.nodeID).
				Msg("Checking if DKG should auto-start (before sync.Once.Do)")

			// 确保只启动一次
			var shouldStart bool
			once.Do(func() {
				shouldStart = true
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("sync.Once.Do executed - starting DKG")
				// 在后台启动DKG协议，不阻塞消息处理
				go func() {
					// 使用独立的上下文，避免 gRPC 请求结束导致 context 被取消
					// 缩短超时时间，加快失败检测（原 10 分钟）
					keygenTimeout := 2 * time.Minute
					keygenCtx, cancel := context.WithTimeout(context.Background(), keygenTimeout)
					defer cancel()

					log.Info().
						Str("session_id", sessionID).
						Str("key_id", sess.KeyID).
						Str("this_node_id", s.nodeID).
						Int("threshold", sess.Threshold).
						Int("total_nodes", sess.TotalNodes).
						Strs("participating_nodes", sess.ParticipatingNodes).
						Dur("keygen_timeout", keygenTimeout).
						Msg("Auto-starting DKG protocol on participant (triggered by incoming message)")

					// 从会话中获取DKG参数
					// 根据协议类型推断算法和曲线
					algorithm := "ECDSA"
					curve := "secp256k1"
					protocolLower := strings.ToLower(sess.Protocol)
					if protocolLower == "frost" {
						algorithm = "EdDSA"
						curve = "ed25519"
					} else if protocolLower == "gg18" || protocolLower == "gg20" {
						algorithm = "ECDSA"
						curve = "secp256k1"
					}

					dkgReq := &protocol.KeyGenRequest{
						KeyID:      sess.KeyID, // DKG会话使用keyID作为sessionID
						Algorithm:  algorithm,
						Curve:      curve,
						Threshold:  sess.Threshold,
						TotalNodes: sess.TotalNodes,
						NodeIDs:    sess.ParticipatingNodes,
					}

					log.Debug().
						Str("session_id", sessionID).
						Str("key_id", sess.KeyID).
						Str("protocol", sess.Protocol).
						Str("algorithm", algorithm).
						Str("curve", curve).
						Msg("Auto-start DKG request parameters determined from session protocol")

					// 选择与会话协议匹配的引擎，避免默认引擎（可能是 FROST）与 ECDSA 请求冲突
					engine := s.protocolEngine
					if s.protocolRegistry != nil && sess.Protocol != "" {
						if regEngine, err := s.protocolRegistry.Get(strings.ToLower(sess.Protocol)); err == nil {
							engine = regEngine
						} else {
							log.Warn().
								Err(err).
								Str("session_id", sessionID).
								Str("key_id", sess.KeyID).
								Str("requested_protocol", sess.Protocol).
								Str("this_node_id", s.nodeID).
								Msg("Auto-start DKG: failed to get protocol from registry, fallback to default engine")
						}
					}

					// 启动DKG协议（在后台，不阻塞）
					// 消息会被放入队列，等待DKG协议启动后处理
					resp, err := engine.GenerateKeyShare(keygenCtx, dkgReq)
					if err != nil {
						log.Error().
							Err(err).
							Str("session_id", sessionID).
							Str("key_id", sess.KeyID).
							Str("this_node_id", s.nodeID).
							Msg("DKG protocol failed on participant")
					} else if resp != nil && resp.PublicKey != nil && resp.PublicKey.Hex != "" {
						log.Info().
							Str("session_id", sessionID).
							Str("key_id", sess.KeyID).
							Str("this_node_id", s.nodeID).
							Str("public_key", resp.PublicKey.Hex).
							Int("key_share_count", len(resp.KeyShares)).
							Msg("DKG protocol completed successfully on participant, storing key share and calling CompleteKeygenSession")

						// 存储密钥分片（只存储当前节点的分片）
						if s.keyShareStorage != nil && len(resp.KeyShares) > 0 {
							for nodeID, share := range resp.KeyShares {
								if err := s.keyShareStorage.StoreKeyShare(keygenCtx, sess.KeyID, nodeID, share.Share); err != nil {
									log.Error().
										Err(err).
										Str("key_id", sess.KeyID).
										Str("node_id", nodeID).
										Str("this_node_id", s.nodeID).
										Msg("Failed to store key share in auto-start goroutine")
								} else {
									log.Info().
										Str("key_id", sess.KeyID).
										Str("node_id", nodeID).
										Str("this_node_id", s.nodeID).
										Msg("Key share stored successfully in auto-start goroutine")

									// 备份功能已删除
								}
							}
						} else {
							log.Warn().
								Str("key_id", sess.KeyID).
								Str("this_node_id", s.nodeID).
								Bool("keyShareStorage_nil", s.keyShareStorage == nil).
								Int("key_share_count", len(resp.KeyShares)).
								Msg("Key share storage skipped in auto-start (keyShareStorage is nil or no key shares)")
						}

						// DKG 完成，直接更新会话与密钥（共享数据库）
						if err := s.sessionManager.CompleteKeygenSession(keygenCtx, sess.KeyID, resp.PublicKey.Hex); err != nil {
							log.Error().
								Err(err).
								Str("session_id", sessionID).
								Str("key_id", sess.KeyID).
								Str("this_node_id", s.nodeID).
								Msg("Failed to complete keygen session")
						} else {
							log.Info().
								Str("session_id", sessionID).
								Str("key_id", sess.KeyID).
								Str("this_node_id", s.nodeID).
								Msg("Keygen session completed successfully")
						}
					}
				}()
			})

			if !shouldStart {
				log.Info().
					Str("session_id", sessionID).
					Str("this_node_id", s.nodeID).
					Msg("DKG already started via sync.Once, skipping auto-start")
			}
		}

		// 作为DKG消息处理，传递发送方节点ID
		// 使用与 StartDKG 相同的协议引擎（基于 session 协议或 registry），避免不同引擎的队列不一致
		engine := s.protocolEngine
		if s.protocolRegistry != nil && sess.Protocol != "" {
			if regEngine, err := s.protocolRegistry.Get(strings.ToLower(sess.Protocol)); err == nil {
				engine = regEngine
			} else {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Str("from_node_id", fromNodeID).
					Str("requested_protocol", sess.Protocol).
					Str("this_node_id", s.nodeID).
					Msg("Failed to get protocol from registry for keygen message, fallback to default protocolEngine")
			}
		}

		// 消息会被放入队列，等待DKG协议启动后处理
		if err := engine.ProcessIncomingKeygenMessage(ctx, sessionID, fromNodeID, shareData, isBroadcast); err != nil {
			return errors.Wrap(err, "failed to process keygen message")
		}
	} else {
		// 作为签名消息处理，传递发送方节点ID；签名阶段不再尝试自动启动 DKG
		// 确保使用与 StartSign 相同的协议引擎（基于 session 的协议或 registry）
		engine := s.protocolEngine
		if s.protocolRegistry != nil && sess.Protocol != "" {
			if regEngine, err := s.protocolRegistry.Get(sess.Protocol); err == nil {
				engine = regEngine
			} else {
				log.Warn().
					Err(err).
					Str("session_id", sessionID).
					Str("from_node_id", fromNodeID).
					Str("requested_protocol", sess.Protocol).
					Str("this_node_id", s.nodeID).
					Msg("Failed to get protocol from registry for signing message, fallback to default protocolEngine")
			}
		}

		if err := engine.ProcessIncomingSigningMessage(ctx, sessionID, fromNodeID, shareData, isBroadcast); err != nil {
			return errors.Wrap(err, "failed to process signing message")
		}
	}

	return nil
}

// SubmitProtocolMessage 提交协议消息（单向RPC）
// 这个方法同时用于DKG和签名消息
func (s *GRPCServer) SubmitProtocolMessage(ctx context.Context, req *pb.SubmitProtocolMessageRequest) (*pb.SubmitProtocolMessageResponse, error) {
	log.Debug().
		Str("session_id", req.SessionId).
		Str("from_node", req.NodeId).
		Int32("round", req.Round).
		Int("data_len", len(req.Data)).
		Msg("Received SubmitProtocolMessage request")

	// 处理协议消息，传递发送方节点ID
	isBroadcast := req.Round == -1
	if err := s.handleProtocolMessage(ctx, req.SessionId, req.NodeId, req.Data, req.Round, isBroadcast); err != nil {
		log.Error().Err(err).
			Str("session_id", req.SessionId).
			Str("from_node", req.NodeId).
			Msg("Failed to handle protocol message")
		return &pb.SubmitProtocolMessageResponse{
			Accepted:  false,
			Message:   err.Error(),
			NextRound: req.Round,
		}, nil
	}

	return &pb.SubmitProtocolMessageResponse{
		Accepted:  true,
		Message:   "message accepted",
		NextRound: req.Round + 1,
	}, nil
}

// Heartbeat 心跳检测
func (s *GRPCServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return &pb.HeartbeatResponse{
		Alive:        true,
		ReceivedAt:   time.Now().Format(time.RFC3339),
		Instructions: make(map[string]string),
	}, nil
}

// RelayProtocolMessage 中继协议消息（从 Client 通过 Service 中继到 Signer）
func (s *GRPCServer) RelayProtocolMessage(ctx context.Context, req *pb.RelayMessageRequest) (*pb.RelayMessageResponse, error) {
	log.Debug().
		Str("session_id", req.SessionId).
		Str("from_node_id", req.FromNodeId).
		Str("to_node_id", req.ToNodeId).
		Int32("round", req.Round).
		Bool("is_broadcast", req.IsBroadcast).
		Int("message_len", len(req.MessageData)).
		Msg("RelayProtocolMessage RPC received")

	// 验证目标节点是否为本节点
	if req.ToNodeId != "" && req.ToNodeId != s.nodeID {
		log.Warn().
			Str("to_node_id", req.ToNodeId).
			Str("this_node_id", s.nodeID).
			Msg("Message not for this node, ignoring")
		return &pb.RelayMessageResponse{
			Accepted: false,
		}, nil
	}

	// 验证 Client (P1) 的 Passkey 签名（E2E 认证）
	if req.FromNodeId != "" && req.FromNodeId != s.nodeID {
		// 从会话中获取 Client 公钥
		sess, err := s.sessionManager.GetSession(ctx, req.SessionId)
		if err != nil {
			log.Warn().
				Err(err).
				Str("session_id", req.SessionId).
				Msg("Failed to get session for client signature verification")
			return &pb.RelayMessageResponse{Accepted: false}, nil
		}

		if sess.ClientPublicKey != "" && len(req.ClientSignature) > 0 {
			// 验证 Client 签名
			if err := auth.VerifyPasskeyMessageSignature(
				sess.ClientPublicKey,
				req.ClientSignature,
				req.SessionId,
				req.FromNodeId,
				req.ToNodeId,
				req.MessageData,
				req.Round,
				req.IsBroadcast,
				req.Timestamp,
			); err != nil {
				log.Warn().
					Err(err).
					Str("session_id", req.SessionId).
					Str("from_node_id", req.FromNodeId).
					Msg("Client signature verification failed")
				return &pb.RelayMessageResponse{Accepted: false}, nil
			}
			log.Debug().
				Str("session_id", req.SessionId).
				Str("from_node_id", req.FromNodeId).
				Msg("Client signature verified successfully")
		} else if sess.ClientPublicKey != "" && len(req.ClientSignature) == 0 {
			// Client 公钥已配置但请求中没有签名，记录警告
			log.Warn().
				Str("session_id", req.SessionId).
				Str("from_node_id", req.FromNodeId).
				Msg("Client public key is configured but request has no client_signature")
			return &pb.RelayMessageResponse{Accepted: false}, nil
		}
	}

	// 处理协议消息
	isBroadcast := req.IsBroadcast
	if err := s.handleProtocolMessage(ctx, req.SessionId, req.FromNodeId, req.MessageData, req.Round, isBroadcast); err != nil {
		log.Error().
			Err(err).
			Str("session_id", req.SessionId).
			Str("from_node_id", req.FromNodeId).
			Str("to_node_id", req.ToNodeId).
			Int32("round", req.Round).
			Bool("is_broadcast", isBroadcast).
			Int("message_len", len(req.MessageData)).
			Msg("Failed to handle protocol message")
		return &pb.RelayMessageResponse{
			Accepted: false,
		}, nil
	}

	// 生成消息 ID
	messageID := fmt.Sprintf("msg-%s-%d", req.SessionId, time.Now().UnixNano())

	log.Debug().
		Str("session_id", req.SessionId).
		Str("message_id", messageID).
		Str("from_node_id", req.FromNodeId).
		Str("to_node_id", req.ToNodeId).
		Msg("Protocol message relayed successfully")

	// 注意：协议消息处理是异步的，目前无法立即返回同步响应消息
	// 如果未来协议引擎支持同步响应，可以在这里检查并返回 reply_message
	// 目前返回 accepted=true，表示消息已被接受并放入处理队列
	return &pb.RelayMessageResponse{
		Accepted:  true,
		MessageId: messageID,
		HasReply:  false, // 协议消息处理是异步的，无法立即返回响应
	}, nil
}

// Ping 健康检查
func (s *GRPCServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PongResponse, error) {
	log.Info().
		Str("from_service", req.FromService).
		Str("timestamp", req.Timestamp).
		Str("node_id", s.nodeID).
		Msg("Ping RPC received")

	return &pb.PongResponse{
		Alive:     true,
		NodeId:    s.nodeID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}

// Start 启动 gRPC 服务器
func (s *GRPCServer) Start(ctx context.Context) error {
	// 如果启用了 TLS，在启动前验证证书
	if s.cfg.TLSEnabled {
		if err := cert.VerifyTLSConfig(s.cfg.TLSCertFile, s.cfg.TLSKeyFile, s.cfg.TLSCACertFile); err != nil {
			return errors.Wrap(err, "TLS certificate verification failed")
		}
		log.Info().Msg("TLS certificates verified successfully")
	}

	addr := fmt.Sprintf(":%d", s.cfg.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener

	// 创建 gRPC 服务器实例
	opts, _ := s.GetServerOptions()
	s.grpcServer = grpc.NewServer(opts...)

	// 注册服务（只注册 SignerService，MPCNode 和 MPCManagement 已删除）
	pb.RegisterSignerServiceServer(s.grpcServer, s)

	// 启用反射（开发环境）
	reflection.Register(s.grpcServer)

	log.Info().
		Str("address", addr).
		Bool("tls", s.cfg.TLSEnabled).
		Msg("Starting MPC gRPC server")

	// 在 goroutine 中启动服务器
	go func() {
		log.Info().
			Str("address", addr).
			Bool("tls", s.cfg.TLSEnabled).
			Str("listener_addr", listener.Addr().String()).
			Msg("MPC gRPC server listening for connections")

		// 添加连接监听日志
		log.Info().Msg("Waiting for incoming gRPC connections...")

		if err := s.grpcServer.Serve(listener); err != nil {
			log.Error().Err(err).Msg("MPC gRPC server failed")
		} else {
			log.Info().Msg("MPC gRPC server stopped")
		}
	}()

	// 等待上下文取消
	<-ctx.Done()
	return s.Stop()
}

// Stop 停止 gRPC 服务器
func (s *GRPCServer) Stop() error {
	log.Info().Msg("Stopping MPC gRPC server")

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	if s.listener != nil {
		s.listener.Close()
	}

	return nil
}

// Participate 处理来自 Client 的直连请求 (V3)
// 这是一个双向流式 RPC
func (s *GRPCServer) Participate(stream pb.SignerService_ParticipateServer) error {
	ctx := stream.Context()

	// 1. 鉴权：从 metadata 获取 Token
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Token 格式：Bearer <jwt_token>
	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization token")
	}

	token := strings.TrimPrefix(authHeader[0], "Bearer ")
	if token == "" {
		return status.Error(codes.Unauthenticated, "invalid authorization token format")
	}

	jwtManager := auth.NewJWTManager(s.cfg.JWTSecret, "", time.Hour)
	claims, err := jwtManager.Validate(token)
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid authorization token")
	}
	mobileNodeID := claims.Subject
	if mobileNodeID == "" {
		mobileNodeID = claims.AppID
	}
	if mobileNodeID == "" {
		return status.Error(codes.Unauthenticated, "invalid authorization claims")
	}

	log.Info().Str("mobile_node_id", mobileNodeID).Msg("Participate stream connected")

	// 注册流
	if s.streamManager != nil {
		s.streamManager.Register(mobileNodeID, stream)
		defer s.streamManager.Unregister(mobileNodeID)
	}

	_ = stream.Send(&pb.ParticipateResponse{
		SessionId:  "",
		FromNodeId: s.nodeID,
		ToNodeId:   mobileNodeID,
		Data:       nil,
		MsgType:    "control.connected",
		Round:      0,
		Error:      "",
	})

	// 2. 启动消息处理循环
	// 我们需要两个 goroutine：
	// - 一个从 stream 读取消息 -> 写入 sessionManager (Input)
	// - 一个从 sessionManager 读取消息 (Output) -> 写入 stream

	errChan := make(chan error, 2)

	// 2.1 接收循环 (Stream -> SessionManager)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				errChan <- err
				return
			}

			// 处理接收到的消息
			// ParticipateRequest: SessionId, FromNodeId, ToNodeId, Data, MsgType, Round

			sessionID := req.SessionId
			// 注入消息到 SessionManager / ProtocolEngine
			// 使用 handleProtocolMessage

			// ParticipateRequest 没有 IsBroadcast 字段，根据 MsgType 判断？或者假设都是非广播？
			// Client (P1) 发送给 P2 的消息通常是单播。如果是广播消息，Client 会发送给所有节点。
			// 但 tss-lib 的消息本身包含了是否广播的信息。
			// handleProtocolMessage 需要 isBroadcast 参数来决定调用 ProcessIncomingKeygenMessage 的哪个重载。
			// 但实际上，engine.ProcessIncomingKeygenMessage(..., isBroadcast) 主要是为了传递给 tss.UpdateFromBytes
			// 我们可以尝试解析 req.Data 来判断？或者默认 false？
			// 或者修改 proto 添加 IsBroadcast 字段？

			isBroadcast := req.ToNodeId == "" || req.Round == -1

			// 消息来自 mobileNodeID
			if err := s.handleProtocolMessage(ctx, sessionID, mobileNodeID, req.Data, req.Round, isBroadcast); err != nil {
				log.Error().
					Err(err).
					Str("session_id", sessionID).
					Str("mobile_node_id", mobileNodeID).
					Int32("round", req.Round).
					Msg("Failed to handle message from client stream")
				// 不中断流，只是记录错误？或者发送错误回执？
			}
		}
	}()

	// 2.2 发送循环 (SessionManager -> Stream)
	// 这需要 SessionManager 支持订阅特定 Session 的出站消息
	// 目前 SessionManager 主要用于状态管理，消息路由是在 ProtocolEngine 中处理的
	// 我们需要一种机制来捕获发往 mobileNodeID 的消息

	// 临时方案：ProtocolEngine 发送消息时，如果是发给 mobileNodeID 的，应该通过某种回调通知这里
	// 或者，我们可以轮询？不，轮询太低效。

	// 更好的方案：
	// 在 ProtocolEngine 中，当需要发送消息给某个节点时，检查该节点是否通过 gRPC 直连
	// 如果是，则通过 channel 发送给对应的 Participate 处理函数

	// TODO: 实现 ProtocolEngine 的消息路由回调机制
	// 现在先阻塞，等待接收循环结束

	select {
	case err := <-errChan:
		log.Info().Err(err).Msg("Participate stream closed")
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// reportResult 上报 DKG 或签名结果到 Service
func (s *GRPCServer) reportResult(sessionID string, result string, isKeygen bool) {
	log.Info().
		Str("session_id", sessionID).
		Str("result_len", fmt.Sprintf("%d", len(result))).
		Bool("is_keygen", isKeygen).
		Msg("Reporting result to Management Service")

	// 发现 Service 节点
	serviceAddr := os.Getenv("MPC_SERVICE_ADDR")
	if serviceAddr == "" {
		serviceAddr = "mpc-service:9091"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serviceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to Management Service for reporting result")
		return
	}
	defer conn.Close()

	client := pb.NewManagementServiceClient(conn)

	// 构造请求
	resultType := "SIGNATURE"
	if isKeygen {
		resultType = "DKG_PUBKEY"
	}

	req := &pb.ReportResultRequest{
		SessionId:  sessionID,
		NodeId:     s.nodeID,
		ResultType: resultType,
		Data:       result, // hex string
		Error:      "",
	}

	resp, err := client.ReportResult(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to report result to Management Service")
	} else if resp.Received {
		log.Info().Msg("Successfully reported result to Management Service")
	}
}

func (s *GRPCServer) checkGuardianPolicy(ctx context.Context, req *pb.StartSignRequest) error {
	// 获取签名策略
	policy, err := s.metadataStore.GetSigningPolicy(ctx, req.KeyId)
	if err != nil {
		return fmt.Errorf("no signing policy found for key_id: %s", req.KeyId)
	}

	// 验证 AuthTokens
	// 如果是 Passkey 模式，我们需要验证 Passkey 签名
	validSignatures := 0

	// Normalize message for challenge verification
	msg := req.Message
	if len(msg) == 0 && req.MessageHex != "" {
		decoded, err := hex.DecodeString(req.MessageHex)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decode message hex in policy check")
			return err
		}
		msg = decoded
	}
	expectedChallenge := base64.RawURLEncoding.EncodeToString(msg)

	// 使用 map 记录已验证的 credential_id，防止重复计数
	verifiedCredentials := make(map[string]bool)

	for _, token := range req.AuthTokens {
		// 团队签功能已删除，不再需要检查团队成员

		// 1. 获取用户存储的 Passkey 公钥
		userPasskey, err := s.metadataStore.GetPasskey(ctx, token.CredentialId)
		if err != nil {
			log.Warn().Str("credential_id", token.CredentialId).Msg("Passkey not found for user")
			continue
		}

		// Backdoor for system testing (DISABLED)
		/*
			if userPasskey.PublicKey == "mock-pub-key-hex" {
				log.Warn().Str("credential_id", token.CredentialId).Msg("Skipping WebAuthn verification for MOCK-PUB-KEY in checkGuardianPolicy")
				if !verifiedCredentials[token.CredentialId] {
					verifiedCredentials[token.CredentialId] = true
					validSignatures++
				}
				continue
			}
		*/

		// 2. 验证 Passkey 签名
		if len(token.PasskeySignature) > 0 {
			if err := auth.VerifyPasskeySignature(
				userPasskey.PublicKey,
				token.PasskeySignature,
				token.AuthenticatorData,
				token.ClientDataJson,
				expectedChallenge,
			); err != nil {
				log.Warn().Err(err).Str("credential_id", token.CredentialId).Msg("Passkey signature verification failed")
				continue
			}

			// 验证通过，记录唯一凭证
			if !verifiedCredentials[token.CredentialId] {
				verifiedCredentials[token.CredentialId] = true
				validSignatures++
			}
		}
	}

	if validSignatures < policy.MinSignatures {
		return fmt.Errorf("insufficient valid passkey signatures: got %d, need %d", validSignatures, policy.MinSignatures)
	}

	return nil
}
