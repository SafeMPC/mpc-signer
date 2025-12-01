package communication

import (
	"context"
	"sync"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	pb "github.com/kashguard/go-mpc-wallet/internal/pb/mpc/v1"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// GRPCClient gRPC客户端，用于节点间通信
type GRPCClient struct {
	mu          sync.RWMutex
	conns       map[string]*grpc.ClientConn
	clients     map[string]pb.MPCNodeClient
	cfg         *ClientConfig
	nodeManager *node.Manager
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
	clientCfg := &ClientConfig{
		TLSEnabled: cfg.MPC.TLSEnabled,
		Timeout:    30 * time.Second,
		KeepAlive:  30 * time.Second,
	}

	return &GRPCClient{
		conns:       make(map[string]*grpc.ClientConn),
		clients:     make(map[string]pb.MPCNodeClient),
		cfg:         clientCfg,
		nodeManager: nodeManager,
	}, nil
}

// getOrCreateConnection 获取或创建到指定节点的连接
func (c *GRPCClient) getOrCreateConnection(ctx context.Context, nodeID string) (pb.MPCNodeClient, error) {
	c.mu.RLock()
	client, ok := c.clients[nodeID]
	c.mu.RUnlock()

	if ok {
		return client, nil
	}

	// 获取节点信息
	nodeInfo, err := c.nodeManager.GetNode(ctx, nodeID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get node info for %s", nodeID)
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
		creds, err := credentials.NewClientTLSFromFile(c.cfg.TLSCACertFile, "")
		if err != nil {
			return nil, errors.Wrap(err, "failed to load TLS credentials")
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
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
	conn, err := grpc.NewClient(nodeInfo.Endpoint, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to node %s at %s", nodeID, nodeInfo.Endpoint)
	}

	// 创建客户端
	client = pb.NewMPCNodeClient(conn)

	// 保存连接和客户端
	c.conns[nodeID] = conn
	c.clients[nodeID] = client

	return client, nil
}

// SendSigningMessage 发送签名协议消息到目标节点
func (c *GRPCClient) SendSigningMessage(ctx context.Context, nodeID string, msg tss.Message) error {
	client, err := c.getOrCreateConnection(ctx, nodeID)
	if err != nil {
		return errors.Wrapf(err, "failed to get connection to node %s", nodeID)
	}

	// 序列化tss-lib消息
	// WireBytes()返回 (wireBytes []byte, routing *MessageRouting, err error)
	msgBytes, _, err := msg.WireBytes()
	if err != nil {
		return errors.Wrap(err, "failed to serialize tss message")
	}

	// 使用SubmitSignatureShare发送消息
	// 注意：这里需要从上下文中获取会话ID
	// 为了简化，我们使用一个占位符
	shareReq := &pb.ShareRequest{
		SessionId: "", // TODO: 需要从上下文中获取会话ID
		NodeId:    nodeID,
		ShareData: msgBytes,
		Round:     0,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	_, err = client.SubmitSignatureShare(ctx, shareReq)
	if err != nil {
		return errors.Wrapf(err, "failed to send signing message to node %s", nodeID)
	}

	return nil
}

// SendKeygenMessage 发送DKG协议消息到目标节点
func (c *GRPCClient) SendKeygenMessage(ctx context.Context, nodeID string, msg tss.Message) error {
	// DKG消息也通过相同的机制发送
	return c.SendSigningMessage(ctx, nodeID, msg)
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
	}

	return nil
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
	c.clients = make(map[string]pb.MPCNodeClient)

	if len(errs) > 0 {
		return errors.Errorf("errors closing connections: %v", errs)
	}

	return nil
}
