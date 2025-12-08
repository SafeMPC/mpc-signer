# 代码重构计划：消除 discovery 和 node 之间的重复

## 问题总结

1. **重复的数据结构**：`ServiceInfo` 和 `ParticipantServiceInfo` 几乎完全重复
2. **不必要的适配器**：`mpcDiscoveryAdapter` 只是在做简单的字段复制
3. **过度抽象**：三层类型转换（Consul → ServiceInfo → ParticipantServiceInfo → Node）

## 重构方案

### 方案 1：直接使用 ServiceInfo（推荐）✅

**优点**：
- 代码最简洁
- 减少类型转换
- 统一的服务信息模型

**步骤**：

1. **删除 `ParticipantServiceInfo`**
   ```go
   // ❌ 删除 internal/mpc/node/discovery.go
   type ParticipantServiceInfo struct { ... }
   ```

2. **修改 `MPCDiscoveryAdapter` 接口**
   ```go
   // internal/mpc/node/discovery.go
   import "github.com/kashguard/go-mpc-wallet/internal/discovery"
   
   type MPCDiscoveryAdapter interface {
       DiscoverParticipants(ctx context.Context, requiredCapabilities []string, count int) ([]*discovery.ServiceInfo, error)
       //                                                                                      ↑ 直接使用 ServiceInfo
   }
   ```

3. **简化转换逻辑**
   ```go
   // internal/mpc/node/discovery.go
   func (d *Discovery) DiscoverNodes(ctx context.Context, nodeType NodeType, status NodeStatus, limit int) ([]*Node, error) {
       // ...
       
       // 从 Consul 发现参与者节点
       services, err := d.mpcDiscovery.DiscoverParticipants(ctx, []string{}, limit)
       // services 的类型是 []*discovery.ServiceInfo
       
       // 直接转换 ServiceInfo → Node
       consulNodes := make([]*Node, 0, len(services))
       for _, svc := range services {
           // 从 Tags 提取 node-id
           nodeID := extractNodeIDFromTags(svc.Tags)
           
           consulNodes = append(consulNodes, &Node{
               NodeID:       nodeID,
               NodeType:     svc.NodeType,
               Endpoint:     fmt.Sprintf("%s:%d", svc.Address, svc.Port),
               Status:       string(status),
               Capabilities: extractCapabilities(svc.Meta),
               Metadata:     convertMeta(svc.Meta),
               RegisteredAt: time.Now(),
           })
       }
       
       return consulNodes, nil
   }
   
   func extractNodeIDFromTags(tags []string) string {
       for _, tag := range tags {
           if strings.HasPrefix(tag, "node-id:") {
               return strings.TrimPrefix(tag, "node-id:")
           }
       }
       return ""
   }
   ```

4. **删除 `mpcDiscoveryAdapter`**
   ```go
   // ❌ 删除 internal/discovery/mpc_discovery.go 中的整个适配器
   type mpcDiscoveryAdapter struct { ... }
   func (m *mpcDiscoveryAdapter) DiscoverParticipants(...) { ... }
   ```

5. **修改 `MPCDiscovery.DiscoverParticipants` 返回类型**
   ```go
   // internal/discovery/mpc_discovery.go
   func (m *MPCDiscovery) DiscoverParticipants(ctx context.Context, requiredCapabilities []string, count int) ([]*ServiceInfo, error) {
       //                                                                                                    ↑ 已经是 ServiceInfo
       return m.Discover(ctx, "mpc-participant", []string{"node-type:participant"})
   }
   ```

### 方案 2：保留 ParticipantServiceInfo 但简化（不推荐）

如果必须保留 `ParticipantServiceInfo`（例如，为了类型安全），至少应该：

1. 让 `ParticipantServiceInfo` 嵌入 `ServiceInfo`
   ```go
   type ParticipantServiceInfo struct {
       *discovery.ServiceInfo
       // 额外的参与者特定字段（如果有）
   }
   ```

2. 简化转换
   ```go
   func toParticipantServiceInfo(svc *discovery.ServiceInfo) *ParticipantServiceInfo {
       return &ParticipantServiceInfo{ServiceInfo: svc}
   }
   ```

## 预期收益

- **减少代码行数**：约 -100 行
- **减少类型转换**：从 3 层减少到 2 层
- **提高可维护性**：单一数据源（ServiceInfo）
- **减少 bug 风险**：更少的类型转换，更少出错

## 实施优先级

**高优先级** - 这是当前 DKG 节点查找失败的根本原因之一！

## 实施建议

1. 先完成此重构
2. 然后修复 DKG 节点查找问题
3. 最后测试 DKG 功能

## 相关文件

- `internal/discovery/interface.go`
- `internal/discovery/mpc_discovery.go`
- `internal/mpc/node/discovery.go`
- `internal/mpc/node/types.go`
