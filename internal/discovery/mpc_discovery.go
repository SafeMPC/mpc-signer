package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/rs/zerolog/log"
)

// MPCDiscovery MPC特定的服务发现
type MPCDiscovery struct {
	registry      *ServiceRegistry
	nodeManager   *node.Manager
	nodeDiscovery *node.Discovery
}

// NewMPCDiscovery 创建MPC服务发现实例
func NewMPCDiscovery(registry *ServiceRegistry, nodeManager *node.Manager, nodeDiscovery *node.Discovery) *MPCDiscovery {
	return &MPCDiscovery{
		registry:      registry,
		nodeManager:   nodeManager,
		nodeDiscovery: nodeDiscovery,
	}
}

// RegisterMPCNode 注册MPC节点到服务发现
func (m *MPCDiscovery) RegisterMPCNode(ctx context.Context, nodeInfo *node.Node) error {
	// 解析 endpoint 获取地址和端口（默认gRPC端口为9090）
	host, port, err := ParseEndpoint(nodeInfo.Endpoint, 9090)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint %s: %w", nodeInfo.Endpoint, err)
	}

	// 转换节点信息为服务信息
	serviceInfo := &ServiceInfo{
		ID:      fmt.Sprintf("mpc-%s-%s", nodeInfo.NodeType, nodeInfo.NodeID),
		Name:    fmt.Sprintf("mpc-%s", nodeInfo.NodeType),
		Address: host,
		Port:    port,
		Tags: []string{
			fmt.Sprintf("node-type:%s", nodeInfo.NodeType),
			fmt.Sprintf("node-id:%s", nodeInfo.NodeID),
			"protocol:v1",
		},
		Meta: map[string]string{
			"node_id":      nodeInfo.NodeID,
			"node_type":    string(nodeInfo.NodeType),
			"endpoint":     nodeInfo.Endpoint,
			"version":      "v1.0.0",
			"capabilities": fmt.Sprintf("%v", nodeInfo.Capabilities),
			"weight":       "1", // 默认权重
		},
		NodeType: string(nodeInfo.NodeType),
		Protocol: "v1",
		Weight:   1,
		Check: &HealthCheck{
			Type:                           "grpc",
			Interval:                       30 * time.Second,
			Timeout:                        5 * time.Second,
			DeregisterCriticalServiceAfter: 5 * time.Minute,
		},
	}

	// 直接使用 discovery 接口注册服务（不通过 registry，因为这是注册其他节点）
	if err := m.registry.discovery.Register(ctx, serviceInfo); err != nil {
		return fmt.Errorf("failed to register MPC node %s: %w", nodeInfo.NodeID, err)
	}

	log.Info().
		Str("node_id", nodeInfo.NodeID).
		Str("node_type", string(nodeInfo.NodeType)).
		Str("service_id", serviceInfo.ID).
		Str("address", host).
		Int("port", port).
		Msg("MPC node registered to service discovery")

	return nil
}

// DiscoverCoordinator 发现Coordinator节点
func (m *MPCDiscovery) DiscoverCoordinator(ctx context.Context) (*ServiceInfo, error) {
	services, err := m.registry.Discover(ctx, "mpc-coordinator", []string{"node-type:coordinator"})
	if err != nil {
		return nil, fmt.Errorf("failed to discover coordinator: %w", err)
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no coordinator found")
	}

	// 返回第一个可用的coordinator
	return services[0], nil
}

// DiscoverParticipants 发现Participant节点
func (m *MPCDiscovery) DiscoverParticipants(ctx context.Context, requiredCapabilities []string, count int) ([]*ServiceInfo, error) {
	tags := []string{"node-type:participant"}

	// 添加能力标签
	for _, capability := range requiredCapabilities {
		tags = append(tags, "capability:"+capability)
	}

	services, err := m.registry.Discover(ctx, "mpc-participant", tags)
	if err != nil {
		return nil, fmt.Errorf("failed to discover participants: %w", err)
	}

	if len(services) < count {
		return nil, fmt.Errorf("insufficient participants: found %d, required %d", len(services), count)
	}

	// 返回指定数量的participants
	if len(services) > count {
		services = services[:count]
	}

	return services, nil
}

// SelectSigningParticipants 选择参与签名的节点
func (m *MPCDiscovery) SelectSigningParticipants(ctx context.Context, keyID string, threshold int, totalNodes int) ([]*ServiceInfo, error) {
	// 首先通过数据库发现节点
	participantNodes, err := m.nodeDiscovery.SelectParticipatingNodes(ctx, threshold, totalNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to select participating nodes from database: %w", err)
	}

	if len(participantNodes) < threshold {
		return nil, fmt.Errorf("insufficient active participants: found %d, required %d", len(participantNodes), threshold)
	}

	// 然后从服务发现中获取最新的状态
	var services []*ServiceInfo
	for _, nodeInfo := range participantNodes {
		service, err := m.registry.SelectService("mpc-participant", []string{
			"node-type:participant",
			"node-id:" + nodeInfo.NodeID,
		}, keyID)

		if err != nil {
			log.Warn().
				Str("node_id", nodeInfo.NodeID).
				Err(err).
				Msg("Failed to get service info for participant")
			continue
		}

		services = append(services, service)
	}

	if len(services) < threshold {
		return nil, fmt.Errorf("insufficient healthy participants: found %d, required %d", len(services), threshold)
	}

	return services, nil
}

// WatchNodeChanges 监听节点变化
func (m *MPCDiscovery) WatchNodeChanges(ctx context.Context) (<-chan []*ServiceInfo, error) {
	// 监听所有MPC节点的变化
	return m.registry.Watch(ctx, "mpc", []string{})
}

// UpdateNodeHealth 更新节点健康状态
func (m *MPCDiscovery) UpdateNodeHealth(ctx context.Context, nodeID string, healthy bool) error {
	// 获取节点的健康状态
	status, err := m.registry.discovery.HealthCheck(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("failed to check node health: %w", err)
	}

	// 更新数据库中的节点状态
	nodeStatus := node.NodeStatusActive
	if !healthy || status.Status != "passing" {
		nodeStatus = node.NodeStatusFaulty
	}

	if err := m.nodeManager.UpdateNodeStatus(ctx, nodeID, nodeStatus); err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}

	log.Info().
		Str("node_id", nodeID).
		Str("health_status", status.Status).
		Str("node_status", string(nodeStatus)).
		Msg("Node health updated")

	return nil
}

// GetServiceStats 获取服务统计信息
func (m *MPCDiscovery) GetServiceStats(ctx context.Context) (*ServiceStats, error) {
	// 获取所有coordinator
	coordinators, err := m.registry.Discover(ctx, "mpc-coordinator", []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get coordinator stats: %w", err)
	}

	// 获取所有participants
	participants, err := m.registry.Discover(ctx, "mpc-participant", []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to get participant stats: %w", err)
	}

	stats := &ServiceStats{
		Coordinators: ServiceGroupStats{
			Total:     len(coordinators),
			Healthy:   countHealthy(ctx, m.registry, coordinators),
			Unhealthy: len(coordinators) - countHealthy(ctx, m.registry, coordinators),
		},
		Participants: ServiceGroupStats{
			Total:     len(participants),
			Healthy:   countHealthy(ctx, m.registry, participants),
			Unhealthy: len(participants) - countHealthy(ctx, m.registry, participants),
		},
	}

	return stats, nil
}

// ServiceStats 服务统计信息
type ServiceStats struct {
	Coordinators ServiceGroupStats `json:"coordinators"`
	Participants ServiceGroupStats `json:"participants"`
}

// ServiceGroupStats 服务组统计
type ServiceGroupStats struct {
	Total     int `json:"total"`
	Healthy   int `json:"healthy"`
	Unhealthy int `json:"unhealthy"`
}

// countHealthy 统计健康的服务数量
func countHealthy(ctx context.Context, registry *ServiceRegistry, services []*ServiceInfo) int {
	healthy := 0
	for _, service := range services {
		// 检查服务的实际健康状态
		status, err := registry.discovery.HealthCheck(ctx, service.ID)
		if err != nil {
			// 如果无法检查健康状态，假设不健康
			log.Debug().
				Str("service_id", service.ID).
				Err(err).
				Msg("Failed to check service health")
			continue
		}

		// 只有状态为 "passing" 才认为是健康的
		if status.Status == "passing" {
			healthy++
		}
	}
	return healthy
}
