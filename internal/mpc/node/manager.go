package node

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SafeMPC/mpc-signer/internal/infra/discovery"
	"github.com/SafeMPC/mpc-signer/internal/infra/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Manager 节点管理器
type Manager struct {
	discoveryService  *discovery.Service
	heartbeatInterval time.Duration
}

// NewManager 创建节点管理器
func NewManager(discoveryService *discovery.Service, heartbeatInterval time.Duration) *Manager {
	return &Manager{
		discoveryService:  discoveryService,
		heartbeatInterval: heartbeatInterval,
	}
}

// RegisterClientNode 注册客户端节点（用于备份）
func (m *Manager) RegisterClientNode(ctx context.Context, userID string, publicKey string, metadata map[string]interface{}) (*Node, error) {
	if userID == "" {
		return nil, errors.New("userID is required")
	}

	nodeID := "client-" + userID
	node := &Node{
		NodeID:       nodeID,
		NodeType:     string(NodeTypeClient),
		Purpose:      string(NodePurposeBackup),
		Endpoint:     "", // 客户端节点不需要端点
		PublicKey:    publicKey,
		Status:       string(NodeStatusActive),
		Capabilities: []string{"backup"},
		Metadata:     metadata,
		RegisteredAt: time.Now(),
	}

	if err := m.RegisterNode(ctx, node); err != nil {
		return nil, errors.Wrap(err, "failed to register client node")
	}

	return node, nil
}

// RegisterNode 注册节点
func (m *Manager) RegisterNode(ctx context.Context, node *Node) error {
	// 设置默认 purpose
	purpose := node.Purpose
	if purpose == "" {
		if node.NodeType == string(NodeTypeClient) {
			purpose = string(NodePurposeBackup)
		} else {
			purpose = string(NodePurposeSigning)
		}
	}

	// Parse endpoint
	var address string
	var port int
	if node.Endpoint != "" {
		parts := strings.Split(node.Endpoint, ":")
		if len(parts) == 2 {
			address = parts[0]
			port, _ = strconv.Atoi(parts[1])
		}
	}

	// Build tags
	tags := []string{
		fmt.Sprintf("node-type:%s", node.NodeType),
		fmt.Sprintf("node-id:%s", node.NodeID),
		"protocol:v1",
	}
	for _, cap := range node.Capabilities {
		tags = append(tags, fmt.Sprintf("cap:%s", cap))
	}

	// Build meta
	meta := make(map[string]string)
	meta["public_key"] = node.PublicKey
	meta["purpose"] = purpose
	meta["status"] = string(node.Status)
	meta["registered_at"] = node.RegisteredAt.Format(time.RFC3339)
	if node.LastHeartbeat != nil {
		meta["last_heartbeat"] = node.LastHeartbeat.Format(time.RFC3339)
	}

	// Flatten metadata
	if node.Metadata != nil {
		for k, v := range node.Metadata {
			if strVal, ok := v.(string); ok {
				meta[k] = strVal
			} else {
				// JSON encode other types
				if bytes, err := json.Marshal(v); err == nil {
					meta[k] = string(bytes)
				}
			}
		}
	}

	service := &discovery.ServiceInfo{
		ID:       fmt.Sprintf("mpc-%s-%s", node.NodeType, node.NodeID),
		Name:     fmt.Sprintf("mpc-%s", node.NodeType),
		Address:  address,
		Port:     port,
		Tags:     tags,
		Meta:     meta,
		NodeType: node.NodeType,
	}

	if err := m.discoveryService.RegisterService(ctx, service); err != nil {
		return errors.Wrap(err, "failed to register node in consul")
	}

	return nil
}

// GetNode 获取节点信息
func (m *Manager) GetNode(ctx context.Context, nodeID string) (*Node, error) {
	// 尝试所有可能的节点类型
	types := []string{"mpc-signer", "mpc-service", "mpc-client"}

	// 优化：根据 ID 前缀猜测类型
	if strings.HasPrefix(nodeID, "client-") {
		types = []string{"mpc-client", "mpc-signer", "mpc-service"}
	}

	for _, serviceName := range types {
		services, err := m.discoveryService.DiscoverServices(ctx, serviceName, []string{fmt.Sprintf("node-id:%s", nodeID)})
		if err != nil {
			log.Warn().Err(err).Str("service_name", serviceName).Msg("Failed to discover services")
			continue
		}
		if len(services) > 0 {
			return m.serviceInfoToNode(services[0]), nil
		}
	}

	return nil, errors.New("node not found")
}

// ListNodes 列出节点
func (m *Manager) ListNodes(ctx context.Context, filter *storage.NodeFilter) ([]*Node, error) {
	var serviceNames []string
	if filter != nil && filter.NodeType != "" {
		serviceNames = []string{fmt.Sprintf("mpc-%s", filter.NodeType)}
	} else {
		serviceNames = []string{"mpc-signer", "mpc-service", "mpc-client"}
	}

	var allNodes []*Node
	for _, serviceName := range serviceNames {
		// Discover services
		// Filter by status if possible via tags? No, status is in Meta.
		// Discover all and filter in memory.
		services, err := m.discoveryService.DiscoverServices(ctx, serviceName, nil)
		if err != nil {
			log.Warn().Err(err).Str("service_name", serviceName).Msg("Failed to list services")
			continue
		}

		for _, svc := range services {
			node := m.serviceInfoToNode(svc)

			// Apply filters
			if filter != nil {
				if filter.NodeType != "" && node.NodeType != filter.NodeType {
					continue
				}
				if filter.Purpose != "" && node.Purpose != filter.Purpose {
					continue
				}
				if filter.Status != "" && node.Status != filter.Status {
					continue
				}
			}

			allNodes = append(allNodes, node)
		}
	}

	// Apply Limit and Offset
	if filter != nil {
		if filter.Offset > 0 {
			if filter.Offset >= len(allNodes) {
				return []*Node{}, nil
			}
			allNodes = allNodes[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(allNodes) {
			allNodes = allNodes[:filter.Limit]
		}
	}

	return allNodes, nil
}

// UpdateNodeStatus 更新节点状态
func (m *Manager) UpdateNodeStatus(ctx context.Context, nodeID string, status NodeStatus) error {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return errors.Wrap(err, "failed to get node")
	}

	node.Status = string(status)
	return m.RegisterNode(ctx, node)
}

// UpdateHeartbeat 更新节点心跳
func (m *Manager) UpdateHeartbeat(ctx context.Context, nodeID string) error {
	// Consul handles heartbeats via checks.
	// Optionally update metadata "last_heartbeat" but this is expensive (re-register).
	// For now, we do nothing or just log.
	// log.Debug().Str("node_id", nodeID).Msg("UpdateHeartbeat called (handled by Consul)")
	return nil
}

// HealthCheck 健康检查
func (m *Manager) HealthCheck(ctx context.Context, nodeID string) (*HealthCheck, error) {
	node, err := m.GetNode(ctx, nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get node")
	}

	checks := make(map[string]string)
	metrics := make(map[string]float64)

	// Check status from node info (which comes from Consul meta)
	if node.Status == string(NodeStatusActive) {
		checks["status"] = "ok"
	} else {
		checks["status"] = "faulty"
	}

	// Since we don't query Consul checks directly here (DiscoverServices uses health/service which returns healthy ones usually),
	// if we found the node via DiscoverServices, it's likely healthy or at least passing checks.
	// But DiscoverServices might return all services depending on implementation.
	// internal/infra/discovery/consul.go uses Health().ServiceMultipleTags(..., true, nil) where true means passingOnly.
	// So if we found it, it's healthy.

	checks["consul"] = "passing"

	return &HealthCheck{
		NodeID:    nodeID,
		Status:    node.Status,
		Checks:    checks,
		Metrics:   metrics,
		Timestamp: time.Now(),
	}, nil
}

// serviceInfoToNode converts discovery.ServiceInfo to Node
func (m *Manager) serviceInfoToNode(svc *discovery.ServiceInfo) *Node {
	// Extract capabilities from tags
	var capabilities []string
	for _, tag := range svc.Tags {
		if strings.HasPrefix(tag, "cap:") {
			capabilities = append(capabilities, strings.TrimPrefix(tag, "cap:"))
		}
	}

	// Extract metadata
	metadata := make(map[string]interface{})
	for k, v := range svc.Meta {
		if k == "public_key" || k == "purpose" || k == "status" || k == "registered_at" || k == "last_heartbeat" {
			continue
		}
		// Try to unmarshal JSON
		var jsonVal interface{}
		if err := json.Unmarshal([]byte(v), &jsonVal); err == nil {
			metadata[k] = jsonVal
		} else {
			metadata[k] = v
		}
	}

	registeredAt, _ := time.Parse(time.RFC3339, svc.Meta["registered_at"])
	var lastHeartbeat *time.Time
	if val, ok := svc.Meta["last_heartbeat"]; ok && val != "" {
		if t, err := time.Parse(time.RFC3339, val); err == nil {
			lastHeartbeat = &t
		}
	}

	// Get NodeID from tag or ID
	nodeID := discovery.ExtractNodeID(svc)

	return &Node{
		NodeID:        nodeID,
		NodeType:      svc.NodeType,
		Purpose:       svc.Meta["purpose"],
		Endpoint:      fmt.Sprintf("%s:%d", svc.Address, svc.Port),
		PublicKey:     svc.Meta["public_key"],
		Status:        svc.Meta["status"],
		Capabilities:  capabilities,
		Metadata:      metadata,
		RegisteredAt:  registeredAt,
		LastHeartbeat: lastHeartbeat,
	}
}
