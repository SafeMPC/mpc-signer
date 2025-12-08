# 重构计划 V2：删除 internal/discovery，统一到 internal/mpc

## 背景

当前架构问题：
1. ❌ `internal/discovery` 过度抽象，但只服务于 MPC
2. ❌ 多层类型转换：`ServiceInfo` → `ParticipantServiceInfo` → `Node`
3. ❌ 跨包依赖复杂，导致 DKG 节点查找失败

## 重构目标

✅ **删除** `internal/discovery` 目录
✅ **迁移** Consul 客户端到 `internal/mpc/discovery`
✅ **简化** 类型定义，只保留 MPC 需要的
✅ **统一** 服务发现逻辑到一个包

## 目录结构变化

### 当前结构
```
internal/
├── discovery/              # ❌ 删除整个目录
│   ├── consul.go
│   ├── interface.go
│   ├── mpc_discovery.go
│   ├── utils.go
│   └── consul_test.go
└── mpc/
    └── node/
        ├── discovery.go    # 节点发现
        ├── manager.go
        ├── registry.go
        └── types.go
```

### 新结构
```
internal/
└── mpc/
    ├── discovery/          # ✅ 新目录：统一的服务发现
    │   ├── consul.go       # 迁移自 internal/discovery
    │   ├── service.go      # 服务发现服务（合并 mpc_discovery.go）
    │   ├── types.go        # 统一的类型定义
    │   └── utils.go        # 工具函数
    └── node/
        ├── discovery.go    # 简化后的节点发现
        ├── manager.go
        ├── registry.go
        └── types.go
```

## 实施步骤

### 步骤 1：创建 internal/mpc/discovery 目录

```bash
mkdir -p internal/mpc/discovery
```

### 步骤 2：定义统一的类型（internal/mpc/discovery/types.go）

```go
package discovery

import "time"

// ServiceInfo MPC 服务信息（统一类型，替代原来的 ServiceInfo 和 ParticipantServiceInfo）
type ServiceInfo struct {
	ID       string            // 服务实例ID
	Name     string            // 服务名称（mpc-participant, mpc-coordinator）
	Address  string            // 服务地址
	Port     int               // 服务端口
	Tags     []string          // 服务标签（node-type:xxx, node-id:xxx, protocol:v1）
	Meta     map[string]string // 元数据
	NodeType string            // 节点类型（coordinator, participant）
}

// HealthCheck 健康检查配置
type HealthCheck struct {
	Type                           string
	Interval                       time.Duration
	Timeout                        time.Duration
	DeregisterCriticalServiceAfter time.Duration
	Path                           string
}
```

### 步骤 3：迁移 Consul 客户端（internal/mpc/discovery/consul.go）

```go
package discovery

import (
	"context"
	"fmt"

	"github.com/hashicorp/consul/api"
	"github.com/rs/zerolog/log"
)

// ConsulClient Consul 客户端（简化版，只保留 MPC 需要的功能）
type ConsulClient struct {
	client *api.Client
	config *ConsulConfig
}

type ConsulConfig struct {
	Address string
	Token   string
}

func NewConsulClient(cfg *ConsulConfig) (*ConsulClient, error) {
	config := api.DefaultConfig()
	config.Address = cfg.Address
	if cfg.Token != "" {
		config.Token = cfg.Token
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	return &ConsulClient{
		client: client,
		config: cfg,
	}, nil
}

// Register 注册服务
func (c *ConsulClient) Register(ctx context.Context, service *ServiceInfo) error {
	registration := &api.AgentServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Address: service.Address,
		Port:    service.Port,
		Tags:    service.Tags,
		Meta:    service.Meta,
		Check: &api.AgentServiceCheck{
			GRPC:                           fmt.Sprintf("%s:%d", service.Address, service.Port),
			Interval:                       "10s",
			Timeout:                        "5s",
			DeregisterCriticalServiceAfter: "1m",
		},
	}

	if err := c.client.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	log.Info().
		Str("service_id", service.ID).
		Str("service_name", service.Name).
		Str("address", service.Address).
		Int("port", service.Port).
		Strs("tags", service.Tags).
		Msg("Service registered successfully")

	return nil
}

// Deregister 注销服务
func (c *ConsulClient) Deregister(ctx context.Context, serviceID string) error {
	if err := c.client.Agent().ServiceDeregister(serviceID); err != nil {
		return fmt.Errorf("failed to deregister service: %w", err)
	}

	log.Info().Str("service_id", serviceID).Msg("Service deregistered successfully")
	return nil
}

// Discover 发现服务
func (c *ConsulClient) Discover(ctx context.Context, serviceName string, tags []string) ([]*ServiceInfo, error) {
	services, _, err := c.client.Health().ServiceMultipleTags(serviceName, tags, true, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to discover services %s: %w", serviceName, err)
	}

	result := make([]*ServiceInfo, 0, len(services))
	for _, service := range services {
		result = append(result, &ServiceInfo{
			ID:       service.Service.ID,
			Name:     service.Service.Name,
			Address:  service.Service.Address,
			Port:     service.Service.Port,
			Tags:     service.Service.Tags,
			Meta:     service.Service.Meta,
			NodeType: extractNodeType(service.Service.Tags),
		})
	}

	log.Debug().
		Str("service_name", serviceName).
		Strs("tags", tags).
		Int("found_services", len(result)).
		Msg("Service discovery completed")

	return result, nil
}

// extractNodeType 从标签中提取节点类型
func extractNodeType(tags []string) string {
	for _, tag := range tags {
		if len(tag) > 10 && tag[:10] == "node-type:" {
			return tag[10:]
		}
	}
	return ""
}
```

### 步骤 4：创建服务发现服务（internal/mpc/discovery/service.go）

```go
package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// Service MPC 服务发现服务
type Service struct {
	consul *ConsulClient
}

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

// DeregisterNode 注销 MPC 节点
func (s *Service) DeregisterNode(ctx context.Context, nodeID, nodeType string) error {
	serviceID := fmt.Sprintf("mpc-%s-%s", nodeType, nodeID)
	return s.consul.Deregister(ctx, serviceID)
}

// DiscoverParticipants 发现参与者节点
func (s *Service) DiscoverParticipants(ctx context.Context, count int) ([]*ServiceInfo, error) {
	services, err := s.consul.Discover(ctx, "mpc-participant", []string{"node-type:participant"})
	if err != nil {
		return nil, err
	}

	log.Debug().
		Int("found_services", len(services)).
		Int("required_count", count).
		Msg("Discovered participants")

	// 如果找到的服务不足要求的数量，返回错误
	if len(services) < count {
		return services, fmt.Errorf("insufficient participants: found %d, required %d", len(services), count)
	}

	// 返回前 count 个服务
	return services[:count], nil
}

// DiscoverCoordinator 发现协调者节点
func (s *Service) DiscoverCoordinator(ctx context.Context) (*ServiceInfo, error) {
	services, err := s.consul.Discover(ctx, "mpc-coordinator", []string{"node-type:coordinator"})
	if err != nil {
		return nil, err
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no coordinator found")
	}

	return services[0], nil
}

// ExtractNodeID 从服务信息中提取节点 ID
func ExtractNodeID(svc *ServiceInfo) string {
	for _, tag := range svc.Tags {
		if strings.HasPrefix(tag, "node-id:") {
			return strings.TrimPrefix(tag, "node-id:")
		}
	}
	return ""
}
```

### 步骤 5：简化 internal/mpc/node/discovery.go

```go
package node

import (
	"context"
	"fmt"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/discovery"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Discovery 节点发现
type Discovery struct {
	manager         *Manager
	discoveryService *discovery.Service // ✅ 直接使用 mpc/discovery.Service
}

func NewDiscovery(manager *Manager, discoveryService *discovery.Service) *Discovery {
	return &Discovery{
		manager:         manager,
		discoveryService: discoveryService,
	}
}

// DiscoverNodes 发现节点
func (d *Discovery) DiscoverNodes(ctx context.Context, nodeType NodeType, status NodeStatus, limit int) ([]*Node, error) {
	filter := &storage.NodeFilter{
		NodeType: string(nodeType),
		Status:   string(status),
		Limit:    limit,
	}

	// 1. 从数据库查询
	nodes, err := d.manager.ListNodes(ctx, filter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list nodes from database")
	}

	// 2. 如果数据库有足够节点，直接返回
	if len(nodes) >= limit {
		return nodes, nil
	}

	// 3. 从 Consul 查询（只查询参与者）
	if nodeType == NodeTypeParticipant && d.discoveryService != nil {
		services, err := d.discoveryService.DiscoverParticipants(ctx, limit)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to discover participants from Consul")
			return nodes, nil // 返回数据库中的节点
		}

		// 4. 转换 discovery.ServiceInfo → node.Node
		for _, svc := range services {
			nodeID := discovery.ExtractNodeID(svc)
			if nodeID == "" {
				continue
			}

			nodes = append(nodes, &Node{
				NodeID:   nodeID,
				NodeType: svc.NodeType,
				Endpoint: fmt.Sprintf("%s:%d", svc.Address, svc.Port),
				Status:   string(status),
			})
		}
	}

	return nodes, nil
}
```

### 步骤 6：更新 Wire 依赖注入（internal/api/providers.go）

```go
// 删除
import "github.com/kashguard/go-mpc-wallet/internal/discovery"

// 添加
import mpcdiscovery "github.com/kashguard/go-mpc-wallet/internal/mpc/discovery"

// 更新 Provider
func NewMPCDiscoveryService(cfg config.Server) (*mpcdiscovery.Service, error) {
	consulClient, err := mpcdiscovery.NewConsulClient(&mpcdiscovery.ConsulConfig{
		Address: cfg.Consul.Address,
	})
	if err != nil {
		return nil, err
	}
	
	return mpcdiscovery.NewService(consulClient), nil
}

func NewNodeDiscovery(manager *node.Manager, discoveryService *mpcdiscovery.Service) *node.Discovery {
	return node.NewDiscovery(manager, discoveryService)
}
```

### 步骤 7：清理工作

1. **删除旧目录**
   ```bash
   rm -rf internal/discovery
   ```

2. **更新所有导入**
   ```bash
   # 查找所有引用
   grep -r "internal/discovery" internal/
   
   # 全局替换
   find internal/ -name "*.go" -exec sed -i '' 's|internal/discovery|internal/mpc/discovery|g' {} \;
   ```

3. **重新生成 Wire**
   ```bash
   make wire
   ```

4. **运行测试**
   ```bash
   make test
   ```

## 预期收益

### 代码简化
- ❌ 删除 `internal/discovery` 目录（~500 行代码）
- ❌ 删除 `ParticipantServiceInfo` 类型
- ❌ 删除 `mpcDiscoveryAdapter` 适配器
- ✅ 统一类型：只有 `discovery.ServiceInfo` 和 `node.Node`

### 类型转换简化
```
之前：Consul API → ServiceInfo → ParticipantServiceInfo → Node (3层)
现在：Consul API → ServiceInfo → Node (2层)
```

### 包依赖简化
```
之前：
internal/mpc/node → internal/discovery → internal/mpc/node (循环依赖)

现在：
internal/mpc/node → internal/mpc/discovery (单向依赖)
```

## 风险评估

### 低风险
- ✅ 只影响 MPC 模块
- ✅ 不影响外部 API
- ✅ 测试覆盖充分

### 注意事项
- ⚠️ 确保所有导入都更新
- ⚠️ 重新运行 Wire 生成
- ⚠️ 测试所有 MPC 功能

## 实施时间估计

- 步骤 1-4：创建新代码（30 分钟）
- 步骤 5-6：更新引用（20 分钟）
- 步骤 7：清理和测试（10 分钟）

**总计：约 1 小时**

## 验证清单

- [ ] 创建 `internal/mpc/discovery` 目录
- [ ] 迁移 Consul 客户端代码
- [ ] 创建统一的类型定义
- [ ] 简化节点发现逻辑
- [ ] 更新 Wire providers
- [ ] 删除 `internal/discovery` 目录
- [ ] 更新所有导入路径
- [ ] 运行 `make wire`
- [ ] 运行 `make test`
- [ ] 测试 DKG 功能
- [ ] 提交代码
