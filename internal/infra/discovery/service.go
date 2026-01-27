package discovery

import (
	"context"
	"fmt"
)

// Service MPC 服务发现服务
type Service struct {
	consul *ConsulClient
}

// NewService 创建 MPC 服务发现服务
func NewService(consul *ConsulClient) *Service {
	return &Service{
		consul: consul,
	}
}

// RegisterNode 注册 MPC 节点
func (s *Service) RegisterNode(ctx context.Context, nodeID, nodeType, address string, port int) error {
	service := &ServiceInfo{
		ID:      fmt.Sprintf("mpc-%s-%s", nodeType, nodeID),
		Name:    fmt.Sprintf("mpc-%s", nodeType),
		Address: address,
		Port:    port,
		Tags: []string{
			fmt.Sprintf("node-type:%s", nodeType),
			fmt.Sprintf("node-id:%s", nodeID),
			"protocol:v1",
		},
		Meta:     make(map[string]string),
		NodeType: nodeType,
	}

	return s.consul.Register(ctx, service)
}

// RegisterService 注册服务 (Generic)
func (s *Service) RegisterService(ctx context.Context, service *ServiceInfo) error {
	return s.consul.Register(ctx, service)
}

// DiscoverServices Generic discovery
func (s *Service) DiscoverServices(ctx context.Context, serviceName string, tags []string) ([]*ServiceInfo, error) {
	return s.consul.Discover(ctx, serviceName, tags)
}

// DeregisterNode 注销 MPC 节点
func (s *Service) DeregisterNode(ctx context.Context, nodeID, nodeType string) error {
	serviceID := fmt.Sprintf("mpc-%s-%s", nodeType, nodeID)
	return s.consul.Deregister(ctx, serviceID)
}

// Signer 不需要发现其他节点的功能
// DiscoverParticipants, DiscoverCoordinator, ExtractNodeID 等方法已删除
// Signer 只需要注册自己到 Consul，由 Service 负责节点发现
