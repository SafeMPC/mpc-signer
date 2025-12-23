package node

import (
	"context"

	"github.com/kashguard/go-mpc-infra/internal/infra/discovery"
	"github.com/kashguard/go-mpc-infra/internal/infra/storage"
	"github.com/pkg/errors"
)

// Discovery 节点发现
type Discovery struct {
	manager          *Manager
	discoveryService *discovery.Service // MPC 服务发现服务
}

// NewDiscovery 创建节点发现器
func NewDiscovery(manager *Manager, discoveryService *discovery.Service) *Discovery {
	return &Discovery{
		manager:          manager,
		discoveryService: discoveryService,
	}
}

// DiscoverNodes 发现节点
// 直接通过 Manager 查询 (Manager 现在只使用 Consul)
func (d *Discovery) DiscoverNodes(ctx context.Context, nodeType NodeType, status NodeStatus, limit int) ([]*Node, error) {
	filter := &storage.NodeFilter{
		NodeType: string(nodeType),
		Status:   string(status),
		Limit:    limit,
		Offset:   0,
	}

	nodes, err := d.manager.ListNodes(ctx, filter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes")
	}

	return nodes, nil
}
