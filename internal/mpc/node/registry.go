package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/pkg/errors"
)

// Registry 节点注册器
type Registry struct {
	manager *Manager
}

// NewRegistry 创建节点注册器
func NewRegistry(manager *Manager) *Registry {
	return &Registry{
		manager: manager,
	}
}

// RegisterService 注册 Service 节点（会话管理/协调，不参与计算）
func (r *Registry) RegisterService(ctx context.Context, endpoint string, publicKey string) (*Node, error) {
	nodeID := generateNodeID("service")

	node := &Node{
		NodeID:       nodeID,
		NodeType:     string(NodeTypeService),
		Endpoint:     endpoint,
		PublicKey:    publicKey,
		Status:       string(NodeStatusActive),
		Capabilities: []string{"gg18", "gg20", "frost"},
		Metadata:     make(map[string]interface{}),
		RegisteredAt: time.Now(),
	}

	if err := r.manager.RegisterNode(ctx, node); err != nil {
		return nil, errors.Wrap(err, "failed to register service")
	}

	return node, nil
}

// RegisterSigner 注册 Signer 节点（参与 MPC 协议计算）
func (r *Registry) RegisterSigner(ctx context.Context, endpoint string, publicKey string, capabilities []string) (*Node, error) {
	nodeID := generateNodeID("signer")

	node := &Node{
		NodeID:       nodeID,
		NodeType:     string(NodeTypeSigner),
		Endpoint:     endpoint,
		PublicKey:    publicKey,
		Status:       string(NodeStatusActive),
		Capabilities: capabilities,
		Metadata:     make(map[string]interface{}),
		RegisteredAt: time.Now(),
	}

	if err := r.manager.RegisterNode(ctx, node); err != nil {
		return nil, errors.Wrap(err, "failed to register signer")
	}

	return node, nil
}

// generateNodeID 生成节点ID
func generateNodeID(prefix string) string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return prefix + "-" + hex.EncodeToString(bytes)
}
