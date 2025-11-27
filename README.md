# go-mpc-wallet — MPC 钱包基础设施

本项目在 go-starter 框架之上实现企业级 MPC（多方安全计算）钱包基座，结合阈值签名 (TSS) 与分层服务架构，为自托管、交易平台、金融机构提供可扩展的密钥管理与签名能力。

## 产品介绍

- **去中心化安全**：密钥永不完整存在，分片通过 DKG 生成并加密存储，服务之间通过策略和审计联动。
- **协议灵活**：抽象 `protocol.Engine` 接口，默认提供 GG18/GG20 封装，可平滑扩展到 FROST、EdDSA 等。
- **模块化扩展**：Key/Signing/Coordinator/Participant/Node 等服务解耦，并通过 Wire 统一注入，便于按需部署与裁剪。
- **链适配层**：提供 Bitcoin、Ethereum 基础适配实现，支持地址生成、交易描述构建，后续可扩展更多链。
- **标准化 API**：采用 Swagger-first 流程生成 REST API，配套 handler、路由与类型校验。

## 已实现功能

- ✅ MPC 配置体系（`internal/config/server_config.go`），支持节点/协议/性能等细粒度参数。
- ✅ 存储层：PostgreSQL 元数据、Redis 会话缓存、AES-GCM 文件密钥分片。
- ✅ 协议引擎接口 + GG18/GG20 协议占位实现。
- ✅ Key/Signing/Coordinator/Participant/Node/Session 核心服务及 DKG 管理。
- ✅ Wire 依赖注入，统一构建所有 MPC 组件。
- ✅ Bitcoin / Ethereum 链适配器基础实现。
- ✅ MPC API（keys、nodes、signing、sessions）及对应 handler 基础版。

## 使用场景

- **托管机构 / 交易平台**：批量管理高价值资产，多节点协作降低私钥泄漏风险。
- **企业级自托管**：B2B 支付、结算平台需要自有密钥基础设施。
- **合规链上操作**：支持审计日志、策略引擎扩展，便于满足合规要求。
- **多链扩展**：通过链适配器快速接入新链或定制业务流程。

## 开发进度

- **Phase 1（MVP）**：核心基础设施基本完成（配置、存储、服务、API、链适配器），剩余任务包括：
  - 补齐部分 Swagger 中定义但尚未实现的 handler（如 `/api/v1/mpc/sessions/{id}/join` 等）。
  - 引入系统化单元测试 / 集成测试。
- **Phase 2 / 3**：包括通用 M-of-N、更多协议、密钥轮换、高可用、性能优化等仍在规划中。

详细计划见 `docs/mpc-development-plan.md`。

## 快速开始

1. **拉取依赖与生成代码**
   ```bash
   go mod download
   SHELL=/bin/sh make swagger   # 确保 swagger/types 最新
   go run github.com/google/wire/cmd/wire ./internal/api
   ```
2. **本地运行（Docker 推荐）**
   ```bash
   docker compose up development
   docker exec -it development /bin/sh -c "cd /app && make build"
   ```
3. **访问 API**
   - REST 前缀：`/api/v1/mpc`
   - Swagger：启动后访问 `/swagger`（若已部署 swagger 静态页）

## 文档

- `docs/mpc-development-plan.md`：分阶段任务、当前状态、优先级。
- `.cursorrules`：MPC 项目的编码规范、架构约束。
- `api/`：Swagger 定义（definitions / paths）与生成配置。

## 贡献

欢迎提交 Issue / PR：在提交前运行 `make swagger && make build`，确保 swagger 与 handlers 保持同步。若需扩展协议、链适配器或策略引擎，请参考 docs 中的模块设计。*** End Patch
