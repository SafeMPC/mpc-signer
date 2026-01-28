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

	"github.com/SafeMPC/mpc-signer/internal/config"
	"github.com/SafeMPC/mpc-signer/internal/mpc/node"
	pb "github.com/SafeMPC/mpc-signer/pb/mpc/v1"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GRPCClient gRPC客户端，用于节点间通信
type GRPCClient struct {
	mu            sync.RWMutex
	conns         map[string]*grpc.ClientConn
	clients       map[string]pb.SignerServiceClient
	mgmtClients   map[string]interface{} // 暂时使用 interface{}，待后续实现
	cfg           *ClientConfig
	nodeManager   *node.Manager
	nodeDiscovery *node.Discovery // 用于从 Consul 发现节点信息
	thisNodeID    string          // 当前节点ID（用于标识消息发送方）
}

// ClientConfig gRPC客户端配置
type ClientConfig struct {
	TLSEnabled    bool
	TLSCertFile   string
	TLSKeyFile    string
	TLSCACertFile string
	Timeout       time.Duration
	KeepAlive     time.Duration
}

// NewGRPCClient 创建gRPC客户端
func NewGRPCClient(cfg config.Server, nodeManager *node.Manager) (*GRPCClient, error) {
	// DKG 协议可能需要较长时间（几分钟），设置更长的超时时间
	// KeepAlive Timeout 设置为 10 分钟，确保长运行的 RPC 调用不会被中断
	clientCfg := &ClientConfig{
		TLSEnabled:    cfg.MPC.TLSEnabled,
		TLSCertFile:   cfg.MPC.TLSCertFile,
		TLSKeyFile:    cfg.MPC.TLSKeyFile,
		TLSCACertFile: cfg.MPC.TLSCACertFile,
		Timeout:       10 * time.Minute, // 增加到 10 分钟
		KeepAlive:     10 * time.Minute, // 增加到 10 分钟
	}

	thisNodeID := cfg.MPC.NodeID
	if thisNodeID == "" {
		thisNodeID = "default-node"
	}

	return &GRPCClient{
		conns:         make(map[string]*grpc.ClientConn),
		clients:       make(map[string]pb.SignerServiceClient),
		mgmtClients:   make(map[string]interface{}),
		cfg:           clientCfg,
		nodeManager:   nodeManager,
		nodeDiscovery: nil, // 稍后通过 SetNodeDiscovery 设置
		thisNodeID:    thisNodeID,
	}, nil
}

// SetNodeDiscovery 设置节点发现器（用于从 Consul 获取节点信息）
func (c *GRPCClient) SetNodeDiscovery(discovery *node.Discovery) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodeDiscovery = discovery
}

// getOrCreateConnection 获取或创建到指定节点的连接
func (c *GRPCClient) getOrCreateConnection(ctx context.Context, nodeID string) (pb.SignerServiceClient, error) {
	c.mu.RLock()
	client, ok := c.clients[nodeID]
	c.mu.RUnlock()

	if ok {
		return client, nil
	}

	// 获取节点信息
	// 首先尝试从数据库获取
	var nodeInfo *node.Node
	var err error
	nodeInfo, err = c.nodeManager.GetNode(ctx, nodeID)
	if err != nil {
		// 如果从数据库获取失败，尝试从 Consul 服务发现中获取
		if c.nodeDiscovery != nil {
			// 从 Consul 发现节点（尝试发现所有类型的节点）
			// 注意：这里我们需要知道节点类型，但暂时尝试 signer 和 service
			for _, nodeType := range []node.NodeType{node.NodeTypeSigner, node.NodeTypeService} {
				// ✅ 使用较小的 limit（与典型参与者数量匹配），并忽略数量不足的错误
				nodes, discoverErr := c.nodeDiscovery.DiscoverNodes(ctx, nodeType, node.NodeStatusActive, 3)
				// 即使返回错误（节点数不足），也可能返回了部分节点，继续查找
				if discoverErr != nil {
					// 忽略数量不足的错误，只要有节点就继续
					if len(nodes) == 0 {
						continue
					}
				}

				// 查找匹配的节点
				for _, n := range nodes {
					if n.NodeID == nodeID {
						nodeInfo = n
						err = nil
						break
					}
				}
				if err == nil {
					break
				}
			}
		}

		// 如果仍然失败，返回错误
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get node info for %s (not found in database or Consul)", nodeID)
		}
	}

	// 创建连接
	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查
	if client, ok := c.clients[nodeID]; ok {
		return client, nil
	}

	// 配置连接选项
	var opts []grpc.DialOption

	// TLS配置
	if c.cfg.TLSEnabled {
		caPath := c.cfg.TLSCACertFile
		if caPath == "" {
			if envPath := os.Getenv("MPC_TLS_CA_CERT_FILE"); envPath != "" {
				caPath = envPath
			} else {
				caPath = "/app/certs/ca.crt"
			}
		}
		certFile := c.cfg.TLSCertFile
		keyFile := c.cfg.TLSKeyFile

		caBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS CA certificate")
		}
		rootCAs := x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("failed to append CA certificate")
		}

		tlsCfg := &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}

		if certFile != "" && keyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, errors.Wrap(err, "failed to load client certificate/key")
			}
			tlsCfg.Certificates = []tls.Certificate{clientCert}
		}

		if host, _, err := net.SplitHostPort(nodeInfo.Endpoint); err == nil && host != "" {
			tlsCfg.ServerName = host
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// KeepAlive配置
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                c.cfg.KeepAlive,
		Timeout:             c.cfg.Timeout,
		PermitWithoutStream: true,
	}))

	// 建立连接
	log.Debug().Str("node_id", nodeID).Str("endpoint", nodeInfo.Endpoint).Msg("Dialing gRPC node")
	conn, err := grpc.DialContext(ctx, nodeInfo.Endpoint, opts...)
	if err != nil {
		log.Error().Err(err).Str("node_id", nodeID).Str("endpoint", nodeInfo.Endpoint).Msg("Failed to connect to gRPC node")
		return nil, errors.Wrapf(err, "failed to connect to node %s at %s", nodeID, nodeInfo.Endpoint)
	}
	log.Debug().Str("node_id", nodeID).Str("endpoint", nodeInfo.Endpoint).Msg("Successfully connected to gRPC node")

	// 创建客户端
	client = pb.NewSignerServiceClient(conn)
	_ = client // mgmtClient 暂时不使用

	// 保存连接和客户端
	c.conns[nodeID] = conn
	c.clients[nodeID] = client
	// mgmtClients 已删除（团队签功能已移除）

	return client, nil
}

// getOrCreateMgmtConnection 获取或创建到指定节点的 Management Client 连接
func (c *GRPCClient) getOrCreateMgmtConnection(ctx context.Context, nodeID string) (interface{}, error) {
	c.mu.RLock()
	client, ok := c.mgmtClients[nodeID]
	c.mu.RUnlock()

	if ok {
		return client, nil
	}

	// 复用连接创建逻辑 (getOrCreateConnection 会初始化两个 Client)
	_, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	client = c.mgmtClients[nodeID]
	c.mu.RUnlock()

	return client, nil
}

// AddWalletMember, RemoveWalletMember, SetSigningPolicy, GetSigningPolicy 已删除（团队签功能已移除）

// SendStartDKG 调用参与者的 StartDKG RPC
func (c *GRPCClient) SendStartDKG(ctx context.Context, nodeID string, req *pb.StartDKGRequest) (*pb.StartDKGResponse, error) {
	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Msg("Sending StartDKG RPC to participant")

	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		log.Error().Err(err).Str("node_id", nodeID).Msg("Failed to get gRPC connection")
		return nil, errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Msg("Calling StartDKG RPC")

	resp, err := client.StartDKG(ctx, req)
	if err != nil {
		log.Error().
			Err(err).
			Str("node_id", nodeID).
			Str("key_id", req.KeyId).
			Msg("StartDKG RPC call failed")
		return nil, err
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Bool("started", resp.Started).
		Str("message", resp.Message).
		Msg("StartDKG RPC call succeeded")

	return resp, nil
}

// SendStartSign 调用参与者的 StartSign RPC
func (c *GRPCClient) SendStartSign(ctx context.Context, nodeID string, req *pb.StartSignRequest) (*pb.StartSignResponse, error) {
	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Msg("Sending StartSign RPC to participant")

	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		log.Error().Err(err).Str("node_id", nodeID).Msg("Failed to get gRPC connection")
		return nil, errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Msg("Calling StartSign RPC")

	resp, err := client.StartSign(ctx, req)
	if err != nil {
		log.Error().
			Err(err).
			Str("node_id", nodeID).
			Str("key_id", req.KeyId).
			Str("session_id", req.SessionId).
			Msg("StartSign RPC call failed")
		return nil, err
	}

	log.Debug().
		Str("node_id", nodeID).
		Str("key_id", req.KeyId).
		Str("session_id", req.SessionId).
		Bool("started", resp.Started).
		Str("message", resp.Message).
		Msg("StartSign RPC call succeeded")

	return resp, nil
}

// SendSigningMessage 发送签名协议消息到目标节点
func (c *GRPCClient) SendSigningMessage(ctx context.Context, nodeID string, msg tss.Message, sessionID string) error {
	// 防止节点向自己发送消息
	if nodeID == c.thisNodeID {
		log.Warn().
			Str("session_id", sessionID).
			Str("node_id", nodeID).
			Str("this_node_id", c.thisNodeID).
			Msg("Attempted to send signing message to self, skipping")
		return nil // 不返回错误，只是跳过
	}

	// 对于移动端节点（mobile-* 或 client-*），直接通过 Service 中继，不尝试直接连接
	isMobileNode := strings.HasPrefix(nodeID, "mobile-") || strings.HasPrefix(nodeID, "client-")

	var client pb.SignerServiceClient
	var err error
	if !isMobileNode {
		// 非移动端节点，尝试直接连接
		client, err = c.getOrCreateConnection(ctx, nodeID)
	}

	if isMobileNode || err != nil {
		// 移动端节点或直接连接失败，通过 Service 中继
		if isMobileNode {
			log.Info().
				Str("session_id", sessionID).
				Str("target_node_id", nodeID).
				Msg("Mobile node detected, routing via Service relay")
		} else {
			log.Warn().
				Err(err).
				Str("session_id", sessionID).
				Str("target_node_id", nodeID).
				Msg("Failed to get direct connection to target node, attempting to relay via Service")
		}

		// 尝试发现 Service 节点
		if c.nodeDiscovery != nil {
			serviceNodes, discoverErr := c.nodeDiscovery.DiscoverNodes(ctx, node.NodeTypeService, node.NodeStatusActive, 1)
			if discoverErr == nil && len(serviceNodes) > 0 {
				serviceNode := serviceNodes[0]
				serviceClient, serviceErr := c.getOrCreateConnection(ctx, serviceNode.NodeID)
				if serviceErr == nil {
					// 通过 Service 中继消息
					msgBytes, _, serializeErr := msg.WireBytes()
					if serializeErr != nil {
						return errors.Wrap(serializeErr, "failed to serialize tss message")
					}

					round := int32(0)
					isBroadcast := len(msg.GetTo()) == 0
					if isBroadcast {
						round = -1
					}

					relayReq := &pb.RelayMessageRequest{
						SessionId:   sessionID,
						FromNodeId:  c.thisNodeID,
						ToNodeId:    nodeID,
						MessageData: msgBytes,
						Round:       round,
						IsBroadcast: isBroadcast,
						Timestamp:   time.Now().Format(time.RFC3339),
					}

					resp, relayErr := serviceClient.RelayProtocolMessage(ctx, relayReq)
					if relayErr == nil && resp.Accepted {
						log.Info().
							Str("session_id", sessionID).
							Str("target_node_id", nodeID).
							Str("service_node_id", serviceNode.NodeID).
							Msg("Successfully relayed signing message via Service")
						return nil
					}
					if relayErr != nil {
						log.Warn().
							Err(relayErr).
							Str("session_id", sessionID).
							Str("target_node_id", nodeID).
							Str("service_node_id", serviceNode.NodeID).
							Msg("Failed to relay message via Service")
					}
				}
			}
		}

		// 如果 Service 中继失败，返回错误
		if isMobileNode {
			return errors.Errorf("failed to relay message to mobile node %s via Service (no Service node available or relay failed)", nodeID)
		}
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 序列化tss-lib消息
	// WireBytes()返回 (wireBytes []byte, routing *MessageRouting, err error)
	msgBytes, routing, err := msg.WireBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize tss message")
	}

	// 确定轮次（tss-lib的MessageRouting可能不包含Round字段，使用0作为默认值）
	// 实际轮次信息可以从消息内容中提取，这里简化处理
	round := int32(0)
	isBroadcast := len(msg.GetTo()) == 0
	if isBroadcast {
		round = -1
	}

	// ✅ 详细日志：记录消息发送详情
	msgType := fmt.Sprintf("%T", msg)
	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", c.thisNodeID).
		Str("target_node_id", nodeID).
		Str("message_type", msgType).
		Int32("round", round).
		Bool("is_broadcast", isBroadcast).
		Int("msg_bytes_len", len(msgBytes)).
		Int("target_count", len(msg.GetTo())).
		Interface("routing", routing).
		Msg("🔍 [DIAGNOSTIC] Sending signing message via gRPC")

	// 使用 RelayProtocolMessage 发送消息（通过 Service 中继）
	req := &pb.RelayMessageRequest{
		SessionId:   sessionID,
		FromNodeId:  c.thisNodeID,
		ToNodeId:    nodeID,
		MessageData: msgBytes,
		Round:       round,
		IsBroadcast: isBroadcast,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	resp, err := client.RelayProtocolMessage(ctx, req)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", sessionID).
			Str("this_node_id", c.thisNodeID).
			Str("target_node_id", nodeID).
			Msg("🔍 [DIAGNOSTIC] Failed to send signing message via gRPC")
		return errors.Wrapf(err, "failed to send signing message to node %s", nodeID)
	}

	log.Info().
		Str("session_id", sessionID).
		Str("this_node_id", c.thisNodeID).
		Str("target_node_id", nodeID).
		Bool("accepted", resp.Accepted).
		Str("message_id", resp.MessageId).
		Msg("🔍 [DIAGNOSTIC] Signing message sent successfully via gRPC")

	return nil
}

// SendKeygenMessage 发送DKG协议消息到目标节点
func (c *GRPCClient) SendKeygenMessage(ctx context.Context, nodeID string, msg tss.Message, sessionID string, isBroadcast bool) error {
	// 防止节点向自己发送消息
	if nodeID == c.thisNodeID {
		log.Warn().
			Str("session_id", sessionID).
			Str("node_id", nodeID).
			Str("this_node_id", c.thisNodeID).
			Msg("Attempted to send DKG message to self, skipping")
		return nil // 不返回错误，只是跳过
	}

	// 对于移动端节点（mobile-* 或 client-*），直接通过 Service 中继，不尝试直接连接
	isMobileNode := strings.HasPrefix(nodeID, "mobile-") || strings.HasPrefix(nodeID, "client-")

	var client pb.SignerServiceClient
	var err error
	if !isMobileNode {
		// 非移动端节点，尝试直接连接
		client, err = c.getOrCreateConnection(ctx, nodeID)
	}

	if isMobileNode || err != nil {
		// 移动端节点或直接连接失败，通过 Service 中继
		if isMobileNode {
			log.Info().
				Str("session_id", sessionID).
				Str("target_node_id", nodeID).
				Msg("Mobile node detected, routing via Service relay")
		} else {
			log.Warn().
				Err(err).
				Str("session_id", sessionID).
				Str("target_node_id", nodeID).
				Msg("Failed to get direct connection to target node, attempting to relay via Service")
		}

		// 尝试发现 Service 节点
		if c.nodeDiscovery != nil {
			serviceNodes, discoverErr := c.nodeDiscovery.DiscoverNodes(ctx, node.NodeTypeService, node.NodeStatusActive, 1)
			if discoverErr != nil {
				log.Warn().
					Err(discoverErr).
					Str("session_id", sessionID).
					Msg("Failed to discover Service node for DKG relay")
			} else if len(serviceNodes) == 0 {
				log.Warn().
					Str("session_id", sessionID).
					Msg("No Service nodes found for DKG message relay")
			} else {
				serviceNode := serviceNodes[0]
				serviceClient, serviceErr := c.getOrCreateConnection(ctx, serviceNode.NodeID)
				if serviceErr != nil {
					log.Error().
						Err(serviceErr).
						Str("session_id", sessionID).
						Str("service_node_id", serviceNode.NodeID).
						Msg("Failed to connect to Service node for DKG message relay")
				} else {
					// 通过 Service 中继消息
					msgBytes, _, serializeErr := msg.WireBytes()
					if serializeErr != nil {
						return errors.Wrap(serializeErr, "failed to serialize tss message")
					}

					round := int32(0)
					if len(msg.GetTo()) == 0 || isBroadcast {
						round = -1
					}

					relayReq := &pb.RelayMessageRequest{
						SessionId:   sessionID,
						FromNodeId:  c.thisNodeID,
						ToNodeId:    nodeID,
						MessageData: msgBytes,
						Round:       round,
						IsBroadcast: isBroadcast,
						Timestamp:   time.Now().Format(time.RFC3339),
					}

					resp, relayErr := serviceClient.RelayProtocolMessage(ctx, relayReq)
					if relayErr != nil {
						log.Error().
							Err(relayErr).
							Str("session_id", sessionID).
							Str("target_node_id", nodeID).
							Str("service_node_id", serviceNode.NodeID).
							Msg("RelayProtocolMessage call failed for DKG")
					} else if resp != nil {
						if resp.Accepted {
							log.Info().
								Str("session_id", sessionID).
								Str("target_node_id", nodeID).
								Str("service_node_id", serviceNode.NodeID).
								Msg("Successfully relayed DKG message via Service")
							return nil
						} else {
							log.Warn().
								Str("session_id", sessionID).
								Str("target_node_id", nodeID).
								Str("service_node_id", serviceNode.NodeID).
								Str("message_id", resp.MessageId).
								Msg("Service rejected DKG relay request")
						}
					}
				}
			}
		}

		// 如果 Service 中继失败，返回错误
		if isMobileNode {
			return errors.Errorf("failed to relay message to mobile node %s via Service (no Service node available or relay failed)", nodeID)
		}
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 序列化tss-lib消息
	msgBytes, _, err := msg.WireBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize tss message")
	}

	// 确定轮次（tss-lib的MessageRouting可能不包含Round字段，使用0作为默认值）
	round := int32(0)
	// 如果 tss 消息没有目标（broadcast）或上层标记为广播，则使用 -1
	if len(msg.GetTo()) == 0 || isBroadcast {
		round = -1
	}

	log.Debug().
		Str("session_id", sessionID).
		Str("target_node_id", nodeID).
		Int("to_count", len(msg.GetTo())).
		Bool("is_broadcast_flag", isBroadcast).
		Int32("round_set", round).
		Msg("Sending DKG ShareRequest via gRPC")

	// 使用 RelayProtocolMessage 发送消息（通过 Service 中继）
	relayReq := &pb.RelayMessageRequest{
		SessionId:   sessionID,
		FromNodeId:  c.thisNodeID,
		ToNodeId:    nodeID,
		MessageData: msgBytes,
		Round:       round,
		IsBroadcast: isBroadcast,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	resp, err := client.RelayProtocolMessage(ctx, relayReq)
	if err != nil {
		return errors.Wrapf(err, "failed to send keygen message to node %s (sessionID: %s)", nodeID, sessionID)
	}

	if !resp.Accepted {
		return errors.Errorf("node %s rejected keygen message", nodeID)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to send keygen message to node %s (sessionID: %s)", nodeID, sessionID)
	}

	if !resp.Accepted {
		return errors.Errorf("node %s rejected keygen message", nodeID)
	}

	// 这是一个非常详细的日志，仅在调试时启用
	// fmt.Printf("Successfully sent keygen message to %s (round: %d, len: %d)\n", nodeID, round, len(msgBytes))

	return nil
}

// SendDKGStartNotification 发送 DKG 启动通知给 participant
func (c *GRPCClient) SendDKGStartNotification(ctx context.Context, nodeID string, sessionID string) error {
	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 发送特殊的 "DKG_START" 消息（通过 Service 中继）
	req := &pb.RelayMessageRequest{
		SessionId:   sessionID,
		FromNodeId:  c.thisNodeID,
		ToNodeId:    nodeID,
		MessageData: []byte("DKG_START"), // 特殊标记，participant 会识别并启动 DKG
		Round:       0,
		IsBroadcast: false,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	_, err = client.RelayProtocolMessage(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "failed to send DKG start notification to node %s (sessionID: %s)", nodeID, sessionID)
	}

	return nil
}

// CloseConnection 关闭到指定节点的连接
func (c *GRPCClient) CloseConnection(nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if conn, ok := c.conns[nodeID]; ok {
		if err := conn.Close(); err != nil {
			return errors.Wrapf(err, "failed to close connection to node %s", nodeID)
		}
		delete(c.conns, nodeID)
		delete(c.clients, nodeID)
		// mgmtClients 已删除（团队签功能已移除）
	}

	return nil
}

// SendStartResharing 密钥轮换功能已删除
func (c *GRPCClient) SendStartResharing(ctx context.Context, nodeID string, req interface{}) (interface{}, error) {
	return nil, errors.New("key rotation (resharing) is not supported")
}

// Close 关闭所有连接
func (c *GRPCClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for nodeID, conn := range c.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, errors.Wrapf(err, "failed to close connection to node %s", nodeID))
		}
	}

	c.conns = make(map[string]*grpc.ClientConn)
	c.clients = make(map[string]pb.SignerServiceClient)
	c.mgmtClients = make(map[string]interface{})

	if len(errs) > 0 {
		return errors.Errorf("errors closing connections: %v", errs)
	}

	return nil
}
