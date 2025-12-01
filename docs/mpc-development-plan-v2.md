# MPC系统完整开发计划 v2.0

**版本**: v2.0  
**创建日期**: 2025-01-02  
**基于**: MPC产品文档 + .cursorrules开发规范 + 当前代码库状态分析

---

## 目标

完成MPC系统的所有功能开发，优先完成DKG功能使系统能够运行，然后逐步完善生产化功能和扩展功能。

## 当前状态

**已完成（约80%）**：
- ✅ 协议引擎（GG18/GG20/FROST + TSS适配器）
- ✅ 基础服务层（Key/Signing/Coordinator/Participant/Node/Session）
- ✅ 所有API handlers（16个）
- ✅ 存储层（PostgreSQL/Redis/密钥分片存储）
- ✅ 分布式通信基础设施（gRPC/服务发现/健康检查）

**未完成（约20%）**：
- ❌ DKG消息接收和处理（最关键）
- ❌ Participant协议参与逻辑
- ❌ Coordinator消息路由
- ❌ 测试覆盖
- ❌ 生产化功能（监控/安全/审计）

---

## Phase 1 MVP剩余功能（优先级：最高）

### 阶段1.1: 完成DKG功能（1-2周）

#### 1.1.1 实现消息接收和处理（3-4天）

**文件**: `internal/mpc/protocol/tss_adapter.go`

**任务**：
1. 在`tssPartyManager`中添加`ProcessIncomingKeygenMessage`方法
   - 接收来自其他节点的DKG消息
   - 解析tss-lib消息格式
   - 更新对应的Party实例状态
   - 处理消息路由错误

2. 在`tssPartyManager`中添加`ProcessIncomingSigningMessage`方法
   - 接收签名协议消息
   - 更新签名Party实例

**关键代码位置**：
- `internal/mpc/protocol/tss_adapter.go` - 添加消息处理方法
- 参考`docs/dkg-implementation-status.md`中的实现建议

#### 1.1.2 实现Coordinator消息路由（2-3天）

**文件**: `internal/mpc/coordinator/service.go`, `internal/mpc/coordinator/protocol_engine.go`

**任务**：
1. 创建`internal/mpc/coordinator/protocol_engine.go`
   - 实现`RouteDKGMessage`方法
   - 实现`RouteSigningMessage`方法
   - 通过gRPC发送消息到Participant节点
   - 处理节点故障和重试

2. 更新`coordinator.Service`
   - 集成消息路由功能
   - 实现节点选择逻辑
   - 实现会话协调逻辑

**关键代码位置**：
- `internal/mpc/coordinator/service.go` - 添加消息路由方法
- 需要创建gRPC客户端连接到Participant节点

#### 1.1.3 实现Participant协议参与（3-4天）

**文件**: `internal/mpc/participant/service.go`, `internal/mpc/participant/protocol_participant.go`

**任务**：
1. 创建`internal/mpc/participant/protocol_participant.go`
   - 实现`ParticipateKeyGen`方法（调用协议引擎）
   - 实现`ParticipateSign`方法
   - 处理协议消息
   - 管理协议状态

2. 更新`participant.Service`
   - 实现`ParticipateKeyGen`方法
   - 实现`ParticipateSign`方法
   - 接收和处理来自Coordinator的消息

**关键代码位置**：
- `internal/mpc/participant/service.go` - 完成TODO方法
- 需要实现gRPC服务端接收消息

#### 1.1.4 实现gRPC通信层（2-3天）

**文件**: `proto/mpc/v1/mpc.proto`, `internal/mpc/communication/grpc_client.go`, `internal/mpc/communication/grpc_server.go`

**任务**：
1. 创建Protocol Buffer定义
   - 定义`MPCNodeService`（节点间通信）
   - 定义`MPCCoordinatorService`（Coordinator服务）
   - 定义消息类型（DKG消息、签名消息）

2. 实现gRPC客户端
   - 创建`internal/mpc/communication/grpc_client.go`
   - 实现消息发送方法
   - 实现连接池管理
   - 实现重试和超时

3. 实现gRPC服务端
   - 创建`internal/mpc/communication/grpc_server.go`
   - 实现消息接收处理
   - 集成到Participant服务

**关键代码位置**：
- 需要创建`proto/mpc/v1/mpc.proto`
- 需要创建`internal/mpc/communication/`目录

#### 1.1.5 完善DKG服务集成（1-2天）

**文件**: `internal/mpc/key/service.go`, `internal/mpc/key/dkg.go`

**任务**：
1. 更新`key.Service.CreateKey`
   - 调用`DKGService.ExecuteDKG`
   - 处理DKG结果
   - 分发密钥分片到节点

2. 完善`DKGService`
   - 实现节点协调逻辑
   - 实现分片验证
   - 实现错误处理和重试

**关键代码位置**：
- `internal/mpc/key/service.go` - 更新CreateKey方法
- `internal/mpc/key/dkg.go` - 完善ExecuteDKG方法

### 阶段1.2: 完善分片管理（1周）

#### 1.2.1 实现分片管理器（3-4天）

**文件**: `internal/mpc/key/share_manager.go`

**任务**：
1. 创建`internal/mpc/key/share_manager.go`
   - 实现分片存储管理
   - 实现分片分发协议
   - 实现分片恢复机制（Shamir秘密共享）
   - 实现分片验证逻辑

**关键代码位置**：
- 需要实现Shamir秘密共享算法
- 参考`internal/mpc/protocol/gg18.go`中的相关逻辑

#### 1.2.2 完善密钥分片存储（2-3天）

**文件**: `internal/mpc/participant/key_share_storage.go`

**任务**：
1. 创建`internal/mpc/participant/key_share_storage.go`
   - 实现分片加密存储
   - 实现分片安全访问
   - 实现访问权限控制
   - 实现分片完整性验证

**关键代码位置**：
- 需要增强`internal/mpc/storage/key_share_storage.go`

### 阶段1.3: 完善Coordinator服务（1周）

#### 1.3.1 实现协议引擎集成（3-4天）

**文件**: `internal/mpc/coordinator/protocol_engine.go`

**任务**：
1. 完善协议引擎调用
   - 实现协议启动逻辑
   - 实现协议状态同步
   - 实现协议错误处理

2. 实现协议消息路由
   - 消息序列化/反序列化
   - 消息广播和点对点发送
   - 消息确认和重传

#### 1.3.2 实现密钥分片管理协调（2-3天）

**文件**: `internal/mpc/coordinator/key_share_manager.go`

**任务**：
1. 创建`internal/mpc/coordinator/key_share_manager.go`
   - 实现分片分发协调
   - 实现分片恢复协调
   - 实现分片验证协调

### 阶段1.4: 完善Participant服务（1周）

#### 1.4.1 实现P2P通信（3-4天）

**文件**: `internal/mpc/participant/p2p_communication.go`

**任务**：
1. 创建`internal/mpc/participant/p2p_communication.go`
   - 实现gRPC通信（节点间）
   - 实现消息认证和加密
   - 实现防重放攻击
   - 实现连接管理

#### 1.4.2 完善协议参与者（2-3天）

**文件**: `internal/mpc/participant/protocol_participant.go`

**任务**：
1. 完善协议消息处理
   - 实现消息验证
   - 实现状态同步
   - 实现错误恢复

### 阶段1.5: 测试和验证（1-2周）

#### 1.5.1 单元测试（3-4天）

**文件**: `internal/mpc/**/*_test.go`

**任务**：
1. 为每个服务模块编写单元测试
   - DKG服务测试
   - 消息路由测试
   - 协议参与测试
   - 分片管理测试

2. 使用mock对象测试依赖
   - Mock gRPC客户端/服务端
   - Mock存储层
   - Mock协议引擎

3. 测试覆盖率 > 70%

#### 1.5.2 集成测试（3-4天）

**文件**: `internal/test/integration/mpc_test.go`

**任务**：
1. 编写端到端集成测试
   - 多节点DKG测试
   - 多节点签名测试
   - 节点故障场景测试
   - 网络分区测试

2. 使用docker-compose搭建测试环境
   - 多个Participant节点
   - Coordinator节点
   - PostgreSQL和Redis

#### 1.5.3 性能测试（2-3天）

**任务**：
1. 签名延迟测试（目标 < 200ms）
2. 并发签名测试（目标 1000+ TPS）
3. 节点故障恢复测试
4. 压力测试

---

## Phase 1+ 生产化功能（2-3周）

### 阶段2.1: 监控和可观测性（1周）

#### 2.1.1 Prometheus监控集成（3-4天）

**文件**: `internal/mpc/metrics/prometheus.go`

**任务**：
1. 集成Prometheus客户端
   - 核心指标收集（签名数、延迟、错误率）
   - 自定义MPC指标（DKG成功率、节点健康度）
   - 性能监控（CPU、内存、网络）

2. 暴露`/metrics`端点
   - 集成到API路由
   - 配置指标收集间隔

#### 2.1.2 结构化日志（2-3天）

**文件**: `internal/mpc/logging/structured.go`

**任务**：
1. 实现结构化日志
   - 请求追踪日志
   - 协议执行日志
   - 错误和异常日志
   - 安全事件日志

2. 集成日志聚合
   - 配置日志格式
   - 配置日志级别
   - 配置日志输出

#### 2.1.3 分布式追踪（2-3天）

**文件**: `internal/mpc/tracing/opentelemetry.go`

**任务**：
1. 集成OpenTelemetry
   - 请求链路追踪
   - 性能瓶颈分析
   - 跨服务追踪

### 阶段2.2: 安全加固（1周）

#### 2.2.1 mTLS认证（3-4天）

**文件**: `internal/mpc/security/tls.go`

**任务**：
1. 实现mTLS认证
   - 证书管理
   - 双向TLS配置
   - 证书轮换机制
   - 证书验证

#### 2.2.2 API访问控制（2-3天）

**文件**: `internal/mpc/auth/rbac.go`

**任务**：
1. 实现基于角色的访问控制
   - 角色定义
   - 权限管理
   - API密钥认证
   - 请求频率限制

### 阶段2.3: 审计日志系统（1周）

#### 2.3.1 审计日志实现（3-4天）

**文件**: `internal/mpc/audit/logger.go`, `internal/mpc/audit/storage.go`

**任务**：
1. 创建审计日志系统
   - 安全事件记录
   - 操作审计追踪
   - 日志完整性保证
   - 日志查询接口

2. 实现审计日志存储
   - PostgreSQL存储
   - 日志加密
   - 日志归档

#### 2.3.2 策略引擎（3-4天）

**文件**: `internal/mpc/policy/engine.go`, `internal/mpc/policy/evaluator.go`

**任务**：
1. 创建策略引擎
   - 策略定义和解析
   - 策略评估引擎
   - 访问控制策略
   - 加密上下文验证

2. 集成到服务层
   - 密钥操作策略检查
   - 签名操作策略检查
   - 节点操作策略检查

---

## Phase 2: 扩展功能（3-4周）

### 阶段3.1: 密钥轮换（1-2周）

#### 3.1.1 密钥轮换协议（1周）

**文件**: `internal/mpc/key/rotation.go`

**任务**：
1. 实现密钥轮换协议
   - 无需重新分发分片的轮换
   - 向后兼容性
   - 平滑过渡机制
   - 轮换验证

### 阶段3.2: 高可用架构（1-2周）

#### 3.2.1 Coordinator高可用（1周）

**文件**: `internal/mpc/coordinator/ha.go`

**任务**：
1. 实现Coordinator高可用
   - 主备模式
   - 领导者选举
   - 故障自动转移
   - 数据同步

#### 3.2.2 负载均衡增强（3-4天）

**任务**：
1. 实现负载均衡
   - 节点负载监控
   - 智能节点选择
   - 故障节点排除

### 阶段3.3: 更多协议和链支持（1周）

#### 3.3.1 EdDSA支持（3-4天）

**文件**: `internal/mpc/protocol/eddsa.go`

**任务**：
1. 实现EdDSA（Ed25519）支持
   - EdDSA密钥生成
   - EdDSA签名

#### 3.3.2 更多链支持（3-4天）

**文件**: `internal/mpc/chain/`

**任务**：
1. 实现EVM链支持（BSC、Avalanche等）
2. 实现Cosmos链支持

---

## Phase 3: 高级功能（2-3周）

### 阶段4.1: 性能优化（1-2周）

#### 4.1.1 并发签名优化（3-4天）

**任务**：
1. 优化并发签名处理
   - Worker池优化
   - 资源管理
   - 并发控制

#### 4.1.2 批量签名优化（3-4天）

**任务**：
1. 优化批量签名
   - 请求合并
   - 批量协议执行
   - 结果批量返回

#### 4.1.3 网络优化（2-3天）

**任务**：
1. 优化网络通信
   - 消息压缩
   - 连接池优化
   - 批量消息发送

### 阶段4.2: 安全增强（1周）

#### 4.2.1 侧信道攻击防护（3-4天）

**任务**：
1. 实现侧信道攻击防护
   - 时间攻击防护
   - 功耗分析防护

#### 4.2.2 恶意节点检测增强（2-3天）

**任务**：
1. 增强恶意节点检测
   - 行为分析
   - 异常检测
   - 自动隔离

---

## 实施优先级

### 立即执行（Phase 1 MVP剩余功能）
1. **DKG消息接收和处理** - 最关键，阻塞系统运行
2. **Coordinator消息路由** - 必需，用于节点通信
3. **Participant协议参与** - 必需，用于分布式协议
4. **gRPC通信层** - 必需，用于节点间通信
5. **测试覆盖** - 必需，确保代码质量

### 短期执行（Phase 1+ 生产化）
6. 监控和可观测性
7. 安全加固
8. 审计日志系统
9. 策略引擎

### 中期执行（Phase 2 扩展功能）
10. 密钥轮换
11. 高可用架构
12. 更多协议和链支持

### 长期执行（Phase 3 高级功能）
13. 性能优化
14. 安全增强

---

## 验收标准

### Phase 1 MVP
- [ ] DKG功能完整，支持多节点密钥生成
- [ ] 阈值签名功能完整，支持2-of-3签名
- [ ] 所有API handlers正常工作
- [ ] 单元测试覆盖率 > 70%
- [ ] 集成测试通过
- [ ] 性能测试满足要求（延迟 < 200ms，吞吐 > 100 TPS）

### Phase 1+ 生产化
- [ ] Prometheus监控集成完成
- [ ] 结构化日志完整
- [ ] mTLS认证实现
- [ ] 审计日志系统完整
- [ ] 策略引擎实现

### Phase 2 扩展功能
- [ ] 密钥轮换功能完整
- [ ] Coordinator高可用实现
- [ ] 支持EdDSA和更多链

### Phase 3 高级功能
- [ ] 性能优化完成（延迟 < 150ms，吞吐 > 1000 TPS）
- [ ] 安全增强完成

---

## 风险评估

### 高风险项
1. **DKG消息处理复杂性** - 需要深入理解tss-lib消息格式
   - 缓解：参考tss-lib文档和示例代码
2. **分布式系统一致性** - 多节点状态同步
   - 缓解：使用成熟的状态机模式，添加验证测试
3. **性能不满足要求** - 签名延迟和吞吐量
   - 缓解：提前性能测试，优化通信协议

### 中风险项
1. **gRPC通信复杂性** - 需要处理网络故障
   - 缓解：封装通信层，提供简单接口，添加重试机制
2. **密钥存储安全** - 分片加密和访问控制
   - 缓解：使用HSM，加密验证，多重备份

---

## 预计时间线

- **Phase 1 MVP剩余功能**: 4-6周
- **Phase 1+ 生产化**: 2-3周
- **Phase 2 扩展功能**: 3-4周
- **Phase 3 高级功能**: 2-3周
- **总计**: 11-16周（约3-4个月）

---

## 成功指标

1. **功能完整性**: 所有计划功能实现完成
2. **代码质量**: 测试覆盖率 > 70%，通过linter检查
3. **性能指标**: 签名延迟 < 200ms，吞吐 > 1000 TPS
4. **安全性**: 通过安全审计，无高危漏洞
5. **可维护性**: 代码文档完整，架构清晰

---

## 任务清单

### Phase 1 MVP剩余功能

#### 阶段1.1: 完成DKG功能
- [ ] 实现DKG消息接收和处理（tss_adapter.go中添加ProcessIncomingKeygenMessage方法）
- [ ] 实现签名消息接收和处理（tss_adapter.go中添加ProcessIncomingSigningMessage方法）
- [ ] 实现Coordinator消息路由（创建protocol_engine.go，实现RouteDKGMessage和RouteSigningMessage）
- [ ] 创建gRPC Protocol Buffer定义（proto/mpc/v1/mpc.proto）
- [ ] 实现gRPC客户端（internal/mpc/communication/grpc_client.go）
- [ ] 实现gRPC服务端（internal/mpc/communication/grpc_server.go）
- [ ] 实现Participant协议参与（创建protocol_participant.go，实现ParticipateKeyGen和ParticipateSign）
- [ ] 完善DKG服务集成（更新key/service.go和key/dkg.go）

#### 阶段1.2: 完善分片管理
- [ ] 实现分片管理器（创建key/share_manager.go，实现Shamir秘密共享）
- [ ] 完善Participant密钥分片存储（创建participant/key_share_storage.go）

#### 阶段1.3: 完善Coordinator服务
- [ ] 完善Coordinator协议引擎集成（创建coordinator/protocol_engine.go）
- [ ] 实现Coordinator密钥分片管理协调（创建coordinator/key_share_manager.go）

#### 阶段1.4: 完善Participant服务
- [ ] 实现Participant P2P通信（创建p2p_communication.go）

#### 阶段1.5: 测试和验证
- [ ] 编写单元测试（覆盖率>70%）
- [ ] 编写集成测试（多节点DKG和签名测试）
- [ ] 性能测试（延迟<200ms，吞吐>100 TPS）

### Phase 1+ 生产化功能

#### 阶段2.1: 监控和可观测性
- [ ] 集成Prometheus监控（internal/mpc/metrics/prometheus.go）
- [ ] 实现结构化日志（internal/mpc/logging/structured.go）
- [ ] 集成分布式追踪（internal/mpc/tracing/opentelemetry.go）

#### 阶段2.2: 安全加固
- [ ] 实现mTLS认证（internal/mpc/security/tls.go）
- [ ] 实现API访问控制（internal/mpc/auth/rbac.go）

#### 阶段2.3: 审计日志系统
- [ ] 实现审计日志系统（internal/mpc/audit/logger.go和storage.go）
- [ ] 实现策略引擎（internal/mpc/policy/engine.go和evaluator.go）

### Phase 2: 扩展功能

#### 阶段3.1: 密钥轮换
- [ ] 实现密钥轮换（internal/mpc/key/rotation.go）

#### 阶段3.2: 高可用架构
- [ ] 实现Coordinator高可用（internal/mpc/coordinator/ha.go）
- [ ] 实现负载均衡增强

#### 阶段3.3: 更多协议和链支持
- [ ] 实现EdDSA支持（internal/mpc/protocol/eddsa.go）
- [ ] 实现更多链支持（BSC、Avalanche、Cosmos）

### Phase 3: 高级功能

#### 阶段4.1: 性能优化
- [ ] 并发签名优化
- [ ] 批量签名优化
- [ ] 网络优化（消息压缩、连接池）

#### 阶段4.2: 安全增强
- [ ] 侧信道攻击防护
- [ ] 恶意节点检测增强

---

**文档维护**: 开发团队  
**最后更新**: 2025-01-02

