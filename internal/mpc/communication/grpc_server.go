package communication

import (
	"context"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// GRPCServer gRPC服务端，用于接收节点间消息
type GRPCServer struct {
	pb.UnimplementedMPCNodeServer

	protocolEngine protocol.Engine
	sessionManager *session.Manager
	nodeID         string
	cfg            *ServerConfig
}

// ServerConfig gRPC服务端配置
type ServerConfig struct {
	TLSEnabled    bool
	TLSCertFile   string
	TLSKeyFile    string
	TLSCACertFile string
	MaxConnAge    time.Duration
	KeepAlive     time.Duration
}

// NewGRPCServer 创建gRPC服务端
func NewGRPCServer(
	cfg config.Server,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	nodeID string,
) *GRPCServer {
	serverCfg := &ServerConfig{
		TLSEnabled: cfg.MPC.TLSEnabled,
		MaxConnAge: 2 * time.Hour,
		KeepAlive:  30 * time.Second,
	}

	return &GRPCServer{
		protocolEngine: protocolEngine,
		sessionManager: sessionManager,
		nodeID:         nodeID,
		cfg:            serverCfg,
	}
}

// GetServerOptions 获取gRPC服务器选项
func (s *GRPCServer) GetServerOptions() ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption

	// TLS配置
	if s.cfg.TLSEnabled {
		creds, err := credentials.NewServerTLSFromFile(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS credentials")
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// KeepAlive配置
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionAge:      s.cfg.MaxConnAge,
		MaxConnectionAgeGrace: 30 * time.Second,
		Time:                  s.cfg.KeepAlive,
		Timeout:               20 * time.Second,
	}))

	// 最大消息大小
	opts = append(opts, grpc.MaxRecvMsgSize(10*1024*1024)) // 10MB
	opts = append(opts, grpc.MaxSendMsgSize(10*1024*1024)) // 10MB

	return opts, nil
}

// JoinSigningSession 双向流：加入签名会话
func (s *GRPCServer) JoinSigningSession(stream grpc.BidiStreamingServer[pb.SessionMessage, pb.SessionMessage]) error {
	ctx := stream.Context()
	var sessionID string

	// 接收初始加入请求
	req, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to receive join request: %v", err)
	}

	// 处理加入请求
	joinReq := req.GetJoinRequest()
	if joinReq == nil {
		return status.Error(codes.InvalidArgument, "first message must be a join request")
	}

	sessionID = joinReq.SessionId

	// 验证会话
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return status.Errorf(codes.NotFound, "session not found: %v", err)
	}

	// 发送确认消息
	confirmation := &pb.SessionConfirmation{
		SessionId:    sessionID,
		Status:       sess.Status,
		Threshold:    int32(sess.Threshold),
		TotalNodes:   int32(sess.TotalNodes),
		Participants: sess.ParticipatingNodes,
		CurrentRound: int32(sess.CurrentRound),
		ConfirmedAt:  time.Now().Format(time.RFC3339),
	}

	if err := stream.Send(&pb.SessionMessage{
		MessageType: &pb.SessionMessage_Confirmation{
			Confirmation: confirmation,
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "failed to send confirmation: %v", err)
	}

	// 处理后续消息
	for {
		msg, err := stream.Recv()
		if err != nil {
			// 流结束
			return nil
		}

		// 处理消息
		if shareMsg := msg.GetShareMessage(); shareMsg != nil {
			// 这是协议消息（DKG或签名）
			if err := s.handleProtocolMessage(ctx, sessionID, shareMsg); err != nil {
				// 发送错误消息
				errorMsg := &pb.ErrorMessage{
					ErrorCode:    "PROTOCOL_ERROR",
					ErrorMessage: err.Error(),
					Recoverable:  true,
					OccurredAt:   time.Now().Format(time.RFC3339),
				}
				if sendErr := stream.Send(&pb.SessionMessage{
					MessageType: &pb.SessionMessage_ErrorMessage{
						ErrorMessage: errorMsg,
					},
				}); sendErr != nil {
					return status.Errorf(codes.Internal, "failed to send error message: %v", sendErr)
				}
				continue
			}
		} else if heartbeatReq := msg.GetHeartbeatRequest(); heartbeatReq != nil {
			// 处理心跳
			heartbeatResp := &pb.HeartbeatResponse{
				Alive:      true,
				ReceivedAt: time.Now().Format(time.RFC3339),
			}
			_ = heartbeatResp // 用于后续扩展
			if err := stream.Send(&pb.SessionMessage{
				MessageType: &pb.SessionMessage_HeartbeatRequest{
					HeartbeatRequest: heartbeatReq,
				},
			}); err != nil {
				return status.Errorf(codes.Internal, "failed to send heartbeat response: %v", err)
			}
		}
	}
}

// handleProtocolMessage 处理协议消息（DKG或签名）
func (s *GRPCServer) handleProtocolMessage(ctx context.Context, sessionID string, shareMsg *pb.ShareMessage) error {
	// 从会话中判断消息类型
	sess, err := s.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return errors.Wrap(err, "failed to get session")
	}

	// 根据协议类型判断是DKG还是签名
	// 这里简化处理，实际应该根据会话的协议类型来判断
	// 如果是keygen会话，调用ProcessIncomingKeygenMessage
	// 如果是signing会话，调用ProcessIncomingSigningMessage

	// 根据会话的Protocol字段判断消息类型
	// 如果Protocol包含"keygen"或"DKG"，则作为DKG消息处理
	// 否则作为签名消息处理
	if sess.Protocol == "keygen" || sess.Protocol == "dkg" {
		// 尝试作为DKG消息处理
		if err := s.protocolEngine.ProcessIncomingKeygenMessage(ctx, sessionID, "", shareMsg.ShareData); err != nil {
			return errors.Wrap(err, "failed to process keygen message")
		}
	} else {
		// 尝试作为签名消息处理
		if err := s.protocolEngine.ProcessIncomingSigningMessage(ctx, sessionID, "", shareMsg.ShareData); err != nil {
			return errors.Wrap(err, "failed to process signing message")
		}
	}

	return nil
}

// SubmitSignatureShare 提交签名分片（单向RPC）
func (s *GRPCServer) SubmitSignatureShare(ctx context.Context, req *pb.ShareRequest) (*pb.ShareResponse, error) {
	// 处理协议消息
	if err := s.handleProtocolMessage(ctx, req.SessionId, &pb.ShareMessage{
		ShareData:   req.ShareData,
		Round:       req.Round,
		SubmittedAt: req.Timestamp,
	}); err != nil {
		return &pb.ShareResponse{
			Accepted:  false,
			Message:   err.Error(),
			NextRound: req.Round,
		}, nil
	}

	return &pb.ShareResponse{
		Accepted:  true,
		Message:   "share accepted",
		NextRound: req.Round + 1,
	}, nil
}

// Heartbeat 心跳检测
func (s *GRPCServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return &pb.HeartbeatResponse{
		Alive:         true,
		CoordinatorId: s.nodeID,
		ReceivedAt:    time.Now().Format(time.RFC3339),
		Instructions:  make(map[string]string),
	}, nil
}
