# MPC系统完整开发计划

**版本**: v1.0  
**创建日期**: 2024  
**基于**: MPC产品文档 + .cursorrules开发规范

---

## 开发策略

**核心原则**：
- **架构设计完整**：支持所有Phase 1-3功能，但先实现MVP
- **使用成熟库**：采用tss-lib（Binance开源）实现协议层，降低开发成本
- **可扩展设计**：所有接口和模块设计支持后续扩展
- **测试驱动**：每个模块都有单元测试和集成测试

### 2025-02 开发进展速览

| 状态 | 完成内容 |
| --- | --- |
| ✅ 已完成 | 依赖与配置体系、数据库迁移、PostgreSQL/Redis/密钥分片存储、协议引擎接口与 GG18/GG20 框架、Key/Signing/Coordinator/Participant/Node/Session 服务、Wire 依赖注入、MPC Swagger + 主要 handlers、Bitcoin/Ethereum 链适配器 |
| 🚧 进行中 | 补齐 Swagger 中剩余的 handler（nodes 列表/健康、sessions join/cancel/address 等）、链级业务完善、单元/集成测试 |
| ⏳ 待启动 | Phase 2+ 的密钥轮换、高可用、更多协议、性能与安全增强 |

**推荐实施顺序**：
1. 先实现Phase 1 MVP（2-of-3阈值签名、GG18/GG20、BTC/ETH支持）
2. 架构设计支持完整功能扩展
3. 后续按需扩展Phase 2和Phase 3功能

---

## Phase 1: 基础架构与MVP（推荐先实现）

### 阶段1.1: 项目基础设置（1周）

#### 1.1.1 依赖管理
- [x] 添加tss-lib依赖到`go.mod`
  - `github.com/binance-chain/tss-lib` (GG18/GG20协议)
  - `github.com/btcsuite/btcd` (Bitcoin支持)
  - `github.com/ethereum/go-ethereum` (Ethereum支持)
  - `github.com/go-redis/redis/v8` (Redis客户端)
- [x] 更新`Makefile`添加MPC相关构建目标

#### 1.1.2 配置管理
- [x] 在`internal/config/server_config.go`添加MPC配置结构
  ```go
  type MPC struct {
      NodeType            string  // 节点类型（coordinator, participant）
      NodeID              string  // 节点ID
      CoordinatorEndpoint string  // Coordinator 端点（Participant 节点需要）
      
      // 存储配置
      StorageBackend      string  // 存储后端类型（postgresql）
      RedisEndpoint       string  // Redis 端点（会话缓存）
      KeyShareStoragePath string  // 密钥分片存储路径
      KeyShareEncryptionKey string // 密钥分片加密密钥
      
      // 协议配置
      SupportedProtocols  []string // 支持的协议（gg18, gg20, frost）
      DefaultProtocol     string   // 默认协议（gg20）
      
      // 服务配置
      HTTPPort            int     // HTTP 端口（默认 8080）
      GRPCPort            int     // gRPC 端口（默认 9090）
      TLSEnabled          bool    // 是否启用 TLS（默认 true）
      
      // 功能配置
      EnableAudit         bool    // 是否启用审计日志（默认 true）
      EnablePolicy        bool    // 是否启用策略引擎（默认 true）
      KeyRotationDays     int     // 密钥自动轮换周期（天，0 表示禁用）
      
      // 性能配置
      MaxConcurrentSessions int   // 最大并发会话数（默认 100）
      MaxConcurrentSignings  int   // 最大并发签名数（默认 50）
      SessionTimeout         int   // 会话超时时间（秒，默认 300）
  }
  ```
- [x] 添加环境变量支持（`.env`文件）

- [x] 创建迁移文件`migrations/YYYYMMDDHHMMSS-create-mpc-tables.sql`
  - `keys`表：密钥元数据（key_id, public_key, algorithm, curve, threshold, total_nodes, chain_type, address, status）
  - `nodes`表：节点信息（node_id, node_type, endpoint, public_key, status, capabilities）
  - `signing_sessions`表：签名会话（session_id, key_id, protocol, status, threshold, participating_nodes, signature）
  - `audit_logs`表：审计日志（扩展现有表，添加node_id, session_id字段）
- [x] 运行`make sql`生成SQLBoiler模型

### 阶段1.2: 存储层实现（1周）

#### 1.2.1 存储接口定义
- [x] 创建`internal/mpc/storage/interface.go`
  - `MetadataStore`接口：密钥元数据存储
  - `KeyShareStorage`接口：密钥分片存储（加密）
  - `SessionStore`接口：签名会话存储（Redis）

#### 1.2.2 PostgreSQL实现
- [x] 实现`internal/mpc/storage/postgresql.go`
  - 使用SQLBoiler模型操作数据库
  - 实现密钥元数据的CRUD操作
  - 实现节点注册和查询

#### 1.2.3 Redis实现
- [x] 实现`internal/mpc/storage/redis.go`
  - 会话状态缓存
  - 分布式锁（用于会话协调）
  - 消息队列（节点间通信）

#### 1.2.4 密钥分片存储
- [x] 实现`internal/mpc/storage/key_share_storage.go`
  - AES-256-GCM加密存储
  - 文件系统存储（每个节点独立存储）
  - 加密密钥管理

### 阶段1.3: 协议引擎封装（1周）

#### 1.3.1 协议接口定义
- [x] 创建`internal/mpc/protocol/engine.go`
  - `Engine`接口：协议引擎抽象
  - 支持协议注册和选择
  - 统一的协议调用接口

#### 1.3.2 GG18/GG20封装
- [ ] 实现`internal/mpc/protocol/gg18.go`
  - 封装tss-lib的GG18协议
  - 实现分布式密钥生成（DKG）
  - 实现阈值签名流程（4轮通信）
- [ ] 实现`internal/mpc/protocol/gg20.go`
  - 封装tss-lib的GG20协议（改进版GG18）

#### 1.3.3 协议适配器
- [ ] 实现协议消息序列化/反序列化
- [ ] 实现协议状态管理
- [ ] 实现错误处理和重试机制

### 阶段1.4: 节点管理（1周）

#### 1.4.1 节点管理器
- [x] 实现`internal/mpc/node/manager.go`
  - 节点注册和发现
  - 节点健康检查
  - 节点状态管理

#### 1.4.2 节点注册
- [x] 实现`internal/mpc/node/registry.go`
  - Coordinator节点注册
  - Participant节点注册
  - 节点认证和授权

#### 1.4.3 节点发现
- [x] 实现`internal/mpc/node/discovery.go`
  - 节点发现机制
  - 节点选择算法（负载均衡）
  - 节点故障检测

### 阶段1.5: 密钥分片管理（1.5周）

#### 1.5.1 密钥服务
- [x] 实现`internal/mpc/key/service.go`
  - 密钥创建（调用DKG）
  - 密钥查询
  - 密钥删除
  - 密钥列表

#### 1.5.2 分布式密钥生成（DKG）
- [ ] 实现`internal/mpc/key/dkg.go`
  - 创建DKG会话
  - 协调所有节点参与
  - 分片生成和验证
  - 分片加密和分发

#### 1.5.3 分片管理
- [ ] 实现`internal/mpc/key/share_manager.go`
  - 分片存储管理
  - 分片分发协议
  - 分片恢复机制（阈值恢复）

### 阶段1.6: 签名会话管理（1周）

#### 1.6.1 会话管理器
- [x] 实现`internal/mpc/session/manager.go`
  - 会话创建
  - 会话状态管理
  - 会话超时处理

#### 1.6.2 会话存储
- [ ] 实现`internal/mpc/session/store.go`
  - Redis会话缓存
  - 会话持久化（PostgreSQL）
  - 会话恢复机制

### 阶段1.7: 阈值签名服务（1.5周）

#### 1.7.1 签名服务
- [ ] 实现`internal/mpc/signing/service.go`
  - 阈值签名接口
  - 批量签名接口
  - 签名验证接口

#### 1.7.2 阈值签名实现
- [ ] 实现`internal/mpc/signing/threshold_sign.go`
  - 创建签名会话
  - 选择参与节点（达到阈值）
  - 执行签名协议（GG18/GG20）
  - 聚合签名分片
  - 验证最终签名

#### 1.7.3 批量签名
- [ ] 实现`internal/mpc/signing/batch_sign.go`
  - 批量签名优化
  - 并发签名处理

### 阶段1.8: Coordinator服务（1周）

#### 1.8.1 Coordinator服务
- [x] 实现`internal/mpc/coordinator/service.go`
  - 协调签名流程
  - 管理签名会话
  - 节点协调

#### 1.8.2 协议引擎集成
- [ ] 实现`internal/mpc/coordinator/protocol_engine.go`
  - 协议引擎调用
  - 协议消息路由

#### 1.8.3 密钥分片管理
- [ ] 实现`internal/mpc/coordinator/key_share_manager.go`
  - 分片分发协调
  - 分片恢复协调

### 阶段1.9: Participant服务（1周）

#### 1.9.1 Participant服务
- [x] 实现`internal/mpc/participant/service.go`
  - 存储密钥分片
  - 参与签名协议
  - 与其他节点通信

#### 1.9.2 密钥分片存储
- [ ] 实现`internal/mpc/participant/key_share_storage.go`
  - 分片加密存储
  - 分片安全访问

#### 1.9.3 协议参与者
- [ ] 实现`internal/mpc/participant/protocol_participant.go`
  - 参与DKG协议
  - 参与签名协议
  - 协议消息处理

#### 1.9.4 P2P通信
- [ ] 实现`internal/mpc/participant/p2p_communication.go`
  - gRPC通信（节点间）
  - 消息认证和加密
  - 防重放攻击

### 阶段1.10: API层实现（1.5周）

#### 1.10.1 API定义（Swagger）
- [x] 创建`api/definitions/mpc.yml`
  - 密钥管理API类型
  - 签名服务API类型
  - 节点管理API类型
  - 会话管理API类型
- [x] 创建`api/paths/mpc.yml`
  - 密钥管理路径
  - 签名服务路径
  - 节点管理路径
  - 会话管理路径
- [x] 更新`api/config/main.yml`添加MPC引用
- [x] 运行`make swagger`生成Go类型

#### 1.10.2 密钥管理Handlers
- [ ] 实现`internal/api/handlers/mpc/keys/post_create_key.go`
- [ ] 实现`internal/api/handlers/mpc/keys/get_key.go`
- [ ] 实现`internal/api/handlers/mpc/keys/delete_key.go`
- [ ] 实现`internal/api/handlers/mpc/keys/get_list_keys.go`
- [ ] 实现`internal/api/handlers/mpc/keys/post_generate_address.go`

#### 1.10.3 签名服务Handlers
- [ ] 实现`internal/api/handlers/mpc/signing/post_sign.go`
- [ ] 实现`internal/api/handlers/mpc/signing/post_batch_sign.go`
- [ ] 实现`internal/api/handlers/mpc/signing/post_verify.go`

#### 1.10.4 节点管理Handlers
- [ ] 实现`internal/api/handlers/mpc/nodes/post_register_node.go`
- [ ] 实现`internal/api/handlers/mpc/nodes/get_node.go`
- [ ] 实现`internal/api/handlers/mpc/nodes/get_list_nodes.go`
- [ ] 实现`internal/api/handlers/mpc/nodes/get_node_health.go`

#### 1.10.5 会话管理Handlers
- [ ] 实现`internal/api/handlers/mpc/sessions/post_create_session.go`
- [ ] 实现`internal/api/handlers/mpc/sessions/post_join_session.go`
- [ ] 实现`internal/api/handlers/mpc/sessions/get_session.go`
- [ ] 实现`internal/api/handlers/mpc/sessions/post_cancel_session.go`

#### 1.10.6 路由注册
- [ ] 更新`internal/api/router/router.go`添加MPC路由
- [ ] 更新`internal/api/handlers/handlers.go`注册所有MPC路由

### 阶段1.11: Wire依赖注入（0.5周）

#### 1.11.1 Provider函数
- [x] 在`internal/api/providers.go`添加MPC服务Providers
  - `NewCoordinatorService`
  - `NewParticipantService`
  - `NewKeyService`
  - `NewSigningService`
  - `NewProtocolEngine`
  - `NewNodeManager`
  - `NewSessionManager`

#### 1.11.2 Wire配置
- [x] 更新`internal/api/wire.go`添加MPC服务集
- [x] 更新`internal/api/server.go`添加MPC服务字段
- [x] 运行`make wire`生成依赖注入代码

### 阶段1.12: 链支持实现（1周）

#### 1.12.1 Bitcoin支持
- [x] 实现`internal/mpc/chain/bitcoin.go`
  - 地址生成（BIP32/BIP44）
  - 交易构建
  - 签名格式转换

#### 1.12.2 Ethereum支持
- [x] 实现`internal/mpc/chain/ethereum.go`
  - 地址生成（从公钥派生）
  - 交易构建（RLP编码）
  - 签名格式转换（EIP-155）

#### 1.12.3 链适配器接口
- [x] 创建`internal/mpc/chain/interface.go`
  - 统一的链接口
  - 支持后续扩展更多链

### 阶段1.13: 测试与文档（1周）

#### 1.13.1 单元测试
- [ ] 为每个服务模块编写单元测试
- [ ] 使用mock对象测试依赖
- [ ] 测试覆盖率 > 70%

#### 1.13.2 集成测试
- [ ] 编写端到端集成测试
- [ ] 测试完整签名流程
- [ ] 测试节点故障场景

#### 1.13.3 文档
- [ ] API文档（Swagger UI）
- [ ] 开发文档（README）
- [ ] 部署文档

---

## Phase 2: 生产化功能（后续扩展）

### 阶段2.1: 通用阈值签名
- [ ] 扩展协议引擎支持任意M-of-N
- [ ] 更新DKG支持动态阈值
- [ ] 更新节点选择算法

### 阶段2.2: 更多协议支持
- [ ] 实现EdDSA（Ed25519）支持
- [ ] 准备FROST协议接口（Phase 3实现）

### 阶段2.3: 更多链支持
- [ ] 实现EVM链支持（BSC、Avalanche等）
- [ ] 实现Cosmos链支持

### 阶段2.4: 密钥轮换
- [ ] 实现密钥轮换协议
- [ ] 支持无需重新分发分片的轮换

### 阶段2.5: 高可用架构
- [ ] 实现Coordinator高可用（主备模式）
- [ ] 实现节点故障自动转移
- [ ] 实现负载均衡

---

## Phase 3: 高级功能（后续扩展）

### 阶段3.1: FROST协议
- [ ] 实现FROST协议（Schnorr签名）
- [ ] 2轮通信优化

### 阶段3.2: 性能优化
- [ ] 并发签名优化
- [ ] 批量签名优化
- [ ] 网络优化

### 阶段3.3: 安全加固
- [ ] 侧信道攻击防护
- [ ] 恶意节点检测增强
- [ ] 安全审计

---

## 技术选型建议

### 协议库
- **tss-lib**: Binance开源，支持GG18/GG20，生产验证
- **优势**: 成熟稳定，降低开发成本
- **使用方式**: 封装使用，不直接暴露给业务层

### 存储
- **PostgreSQL**: 元数据存储（已有）
- **Redis**: 会话缓存（需添加）
- **文件系统**: 密钥分片加密存储

### 通信
- **gRPC**: 节点间高效通信
- **HTTP/REST**: 客户端API（已有Echo框架）

---

## 开发优先级

**必须实现（MVP）**：
1. 基础架构（存储、配置）
2. 协议引擎封装（GG18/GG20）
3. 密钥分片管理（DKG）
4. 阈值签名服务（2-of-3）
5. Coordinator和Participant服务
6. API层（RESTful）
7. Bitcoin和Ethereum支持

**可以延后**：
- 批量签名优化
- 高级监控
- 管理控制台
- 多语言SDK

---

## 测试策略

1. **单元测试**: 每个服务模块独立测试
2. **集成测试**: 测试完整签名流程
3. **压力测试**: 测试并发签名性能
4. **故障测试**: 测试节点故障场景

---

## 风险控制

1. **使用成熟库**: tss-lib已经过生产验证
2. **分阶段实施**: 先MVP后扩展
3. **完整测试**: 每个阶段都有测试
4. **安全审计**: 关键模块进行安全审查

---

## 时间估算

**Phase 1 MVP总时间**: 约13周（3个月）

- 阶段1.1: 1周
- 阶段1.2: 1周
- 阶段1.3: 1周
- 阶段1.4: 1周
- 阶段1.5: 1.5周
- 阶段1.6: 1周
- 阶段1.7: 1.5周
- 阶段1.8: 1周
- 阶段1.9: 1周
- 阶段1.10: 1.5周
- 阶段1.11: 0.5周
- 阶段1.12: 1周
- 阶段1.13: 1周

**Phase 2**: 约8-10周（2-2.5个月）  
**Phase 3**: 约6-8周（1.5-2个月）

---

## 关键里程碑

1. **Milestone 1**: 完成基础架构和存储层（阶段1.1-1.2）
2. **Milestone 2**: 完成协议引擎和节点管理（阶段1.3-1.4）
3. **Milestone 3**: 完成密钥分片管理和签名服务（阶段1.5-1.7）
4. **Milestone 4**: 完成Coordinator和Participant服务（阶段1.8-1.9）
5. **Milestone 5**: 完成API层和链支持（阶段1.10-1.12）
6. **Milestone 6**: 完成测试和文档（阶段1.13）- **MVP完成**

---

## 注意事项

1. **遵循.cursorrules规范**: 所有代码必须遵循项目开发规范
2. **Wire依赖注入**: 所有服务必须使用Wire进行依赖注入
3. **Swagger-First**: API开发必须遵循Swagger-First模式
4. **安全第一**: 密钥分片加密存储，永不完整存在
5. **测试覆盖**: 每个模块都要有测试，覆盖率>70%
6. **文档同步**: 代码和文档同步更新

---

**文档维护**: 开发团队  
**最后更新**: 2024

