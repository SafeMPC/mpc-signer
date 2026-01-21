# MPC Signer Node

> MPC 签名节点 - 执行 MPC 协议计算的节点（纯 gRPC 服务）

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](go.mod)

**mpc-signer** 是 MPC 钱包系统中的签名节点，负责执行 MPC 协议计算（DKG 和阈值签名）。

---

## 🎯 节点职责

### 核心功能
- ✅ **执行 MPC 协议**: 参与 DKG（分布式密钥生成）和阈值签名协议
- ✅ **存储密钥分片**: 安全存储 P2 密钥分片（加密存储在 Nitro Enclave）
- ✅ **gRPC 服务**: 接收来自 mpc-service 的请求
- ✅ **协议支持**: 支持 GG20 (ECDSA) 和 FROST (EdDSA) 协议

### 不提供的功能
- ❌ **REST API**: 不提供 HTTP API
- ❌ **用户认证**: 不处理用户认证（由 Service 负责）
- ❌ **直接客户端访问**: 不接受来自 Client 的直接请求

---

## 🏗️ 架构说明

### 通信模式

```
Client (P1)
    │
    │ REST + WebSocket
    │
    ▼
Service (mpc-service)
    │
    │ gRPC + mTLS + Service Token
    │
    ▼
Signer (mpc-signer)
    │
    │ 内网 TEE
    │ AWS Nitro Enclave
```

### 2-of-2 模式
- **手机端 P1**: 作为 Signer 节点（通过 Service 中继）
- **服务器端 P2**: 本服务

mpc-signer 只负责执行 MPC 协议计算，不负责会话管理、API 服务等协调工作（这些由 mpc-service 节点负责）。

---

## 🔌 gRPC 接口

### SignerService

```protobuf
service SignerService {
  // DKG 相关
  rpc StartDKG(StartDKGRequest) returns (StartDKGResponse);
  rpc GetDKGStatus(GetDKGStatusRequest) returns (DKGStatusResponse);
  
  // 签名相关
  rpc StartSign(StartSignRequest) returns (StartSignResponse);
  rpc GetSignStatus(GetSignStatusRequest) returns (SignStatusResponse);
  
  // 协议消息处理
  rpc SubmitProtocolMessage(ProtocolMessageRequest) returns (ProtocolMessageResponse);
  
  // 健康检查
  rpc Ping(PingRequest) returns (PongResponse);
}
```

**完整定义**: 参见 `proto/mpc/v1/signer.proto`

---

## 🔒 安全机制

### 1. 网络隔离
- 部署在 **AWS VPC Private Subnet**
- 不暴露公网端口
- 只接受来自 Service 的内网连接

### 2. mTLS 认证
```yaml
grpc:
  tls_enabled: true
  cert_file: "/app/certs/signer.crt"
  key_file: "/app/certs/signer.key"
  ca_cert: "/app/certs/ca.crt"
  client_auth: "require"  # 要求客户端证书
```

### 3. Service Token 验证
- 验证来自 Service 的 JWT token
- 检查 token 的 audience、issuer、有效期
- 拒绝未授权的请求

### 4. 消息签名验证
- 验证协议消息的 HMAC 签名
- 防止消息被篡改
- 确保消息来自可信的 Service

---

## 🚀 快速开始

### 环境要求
- Go 1.21+
- Docker & Docker Compose
- 连接到 mpc-service 的网络

### 启动服务

```bash
cd mpc-signer
docker compose up -d server-signer-p2
```

### 配置

Signer 通过环境变量连接到 Service 的基础设施：

```yaml
MPC_NODE_TYPE: "signer"
MPC_NODE_ID: "server-signer-p2"
MPC_SERVICE_ENDPOINT: "host.docker.internal:9090"
MPC_CONSUL_ADDRESS: "host.docker.internal:8500"
PGHOST: "host.docker.internal"
MPC_REDIS_ENDPOINT: "host.docker.internal:6379"
```

### 健康检查

```bash
# 通过 gRPC 健康检查
grpcurl -plaintext localhost:9091 mpc.v1.SignerService/Ping
```

---

## 📁 目录结构

```
mpc-signer/
├── internal/
│   ├── config/              # 配置管理
│   ├── infra/
│   │   ├── signing/        # 签名服务
│   │   ├── dkg/            # DKG 服务
│   │   ├── session/        # 会话管理
│   │   └── storage/        # 密钥分片存储
│   └── mpc/
│       ├── protocol/        # 协议引擎（GG20/FROST）
│       ├── grpc/            # gRPC Server（核心）
│       ├── node/            # 节点管理
│       └── chain/           # 链适配器
├── proto/mpc/v1/           # gRPC 定义
├── pb/mpc/v1/              # 生成的 pb 文件
├── main.go                 # 启动入口
└── docker-compose.yml      # Docker 配置
```

**注意**: 没有 `api/` 目录和 `handlers/` 目录！

---

## 🔧 开发

### 编译
```bash
make build
```

### 测试
```bash
make test
```

### 进入容器
```bash
docker compose exec server-signer-p2 bash
```

---

## 📖 相关文档

- [V2 架构设计](../design/docs/ARCHITECTURE_V2.md)
- [接口设计](../design/docs/INTERFACE_DESIGN.md)
- [开发规范](../.cursorrules)
- [Service 节点](../mpc-service/README.md)

---

## ⚠️ 重要说明

### Signer 是纯后端服务
- 没有用户界面
- 没有 REST API
- 只通过 gRPC 与 Service 通信

### 部署建议
- AWS Nitro Enclave
- VPC Private Subnet
- 通过 VPN 或 AWS PrivateLink 连接到 Service

---

**Signer = gRPC Server + MPC 计算引擎** 🔐
