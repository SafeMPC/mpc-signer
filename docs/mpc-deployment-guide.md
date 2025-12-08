# MPC 节点部署指南

本指南说明如何使用 `docker-compose.yml` 部署一个协调者（Coordinator）和三个参与者（Participant）节点。

## 架构概览

部署架构包含：
- **1个 Coordinator 节点**：协调 MPC 协议执行
- **3个 Participant 节点**：存储密钥分片，参与签名
- **共享基础设施**：PostgreSQL、Consul、Redis

## 服务端口分配

| 服务 | HTTP 端口 | gRPC 端口 | 节点ID |
|------|-----------|-----------|--------|
| coordinator | 8080 | 9090 | coordinator-1 |
| participant-1 | 8081 | 9091 | participant-1 |
| participant-2 | 8082 | 9092 | participant-2 |
| participant-3 | 8083 | 9093 | participant-3 |

## 部署步骤

### 1. 前置准备

确保已安装：
- Docker
- Docker Compose

### 2. 构建并启动所有服务

```bash
# 构建并启动所有服务（后台运行）
docker-compose up -d --build

# 或者前台运行（查看日志）
docker-compose up --build
```

### 3. 查看服务状态

```bash
# 查看所有服务状态
docker-compose ps

# 查看特定服务状态
docker-compose ps coordinator
docker-compose ps participant-1
```

### 4. 查看日志

```bash
# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f coordinator
docker-compose logs -f participant-1
docker-compose logs -f participant-2
docker-compose logs -f participant-3

# 查看最近100行日志
docker-compose logs --tail=100 coordinator
```

### 5. 验证服务健康状态

```bash
# 检查 Coordinator 健康状态
curl http://localhost:8080/-/healthy

# 检查 Participant-1 健康状态
curl http://localhost:8081/-/healthy

# 检查 Participant-2 健康状态
curl http://localhost:8082/-/healthy

# 检查 Participant-3 健康状态
curl http://localhost:8083/-/healthy
```

### 6. 验证节点注册到 Consul

1. 打开 Consul UI：http://localhost:8500
2. 在 Services 页面查看：
   - `mpc-coordinator` 服务（1个实例）
   - `mpc-participant` 服务（3个实例）

所有节点应在启动时自动注册到 Consul，关闭时自动注销。

## 服务访问地址

### HTTP API

- Coordinator: http://localhost:8080
- Participant-1: http://localhost:8081
- Participant-2: http://localhost:8082
- Participant-3: http://localhost:8083

### 管理界面

- Consul UI: http://localhost:8500
- Swagger UI: http://localhost:8081 (通过 swaggerui-browser-sync)
- MailHog UI: http://localhost:8025

### 数据库

- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## 常用操作

### 重启特定服务

```bash
# 重启 Coordinator
docker-compose restart coordinator

# 重启所有 Participant
docker-compose restart participant-1 participant-2 participant-3
```

### 停止服务

```bash
# 停止所有服务（保留数据卷）
docker-compose stop

# 停止并删除容器（保留数据卷）
docker-compose down

# 停止并删除容器和数据卷（⚠️ 警告：会删除所有数据）
docker-compose down -v
```

### 进入容器

```bash
# 进入 Coordinator 容器
docker-compose exec coordinator /bin/sh

# 进入 Participant-1 容器
docker-compose exec participant-1 /bin/sh
```

### 查看服务依赖关系

```bash
# 查看服务依赖图
docker-compose config
```

## 配置说明

### 环境变量

每个节点的主要配置通过环境变量设置：

**Coordinator 配置**：
- `MPC_NODE_TYPE=coordinator`
- `MPC_NODE_ID=coordinator-1`
- `MPC_HTTP_PORT=8080`
- `MPC_GRPC_PORT=9090`

**Participant 配置**：
- `MPC_NODE_TYPE=participant`
- `MPC_NODE_ID=participant-{1,2,3}`
- `MPC_COORDINATOR_ENDPOINT=coordinator:9090`
- `MPC_HTTP_PORT=808{1,2,3}`
- `MPC_GRPC_PORT=909{1,2,3}`

### 密钥分片存储

每个节点使用独立的 Docker 卷存储密钥分片：
- `coordinator-key-shares`
- `participant1-key-shares`
- `participant2-key-shares`
- `participant3-key-shares`

这确保了密钥分片的隔离和安全。

### 健康检查

所有 MPC 节点都配置了健康检查：
- 检查间隔：10秒
- 超时时间：5秒
- 重试次数：3次
- 启动等待期：30秒

## 故障排查

### 服务无法启动

1. **检查日志**：
   ```bash
   docker-compose logs coordinator
   ```

2. **检查依赖服务**：
   ```bash
   # 确保 PostgreSQL 健康
   docker-compose ps postgres
   
   # 确保 Consul 健康
   docker-compose ps consul
   ```

3. **检查端口冲突**：
   ```bash
   # 检查端口是否被占用
   lsof -i :8080
   lsof -i :8081
   ```

### 节点未注册到 Consul

1. **检查 Consul 连接**：
   ```bash
   docker-compose logs coordinator | grep -i consul
   ```

2. **检查 Consul 服务**：
   ```bash
   docker-compose ps consul
   curl http://localhost:8500/v1/status/leader
   ```

3. **手动检查注册**：
   访问 Consul UI (http://localhost:8500) 查看服务列表

### 节点间无法通信

1. **检查网络连接**：
   ```bash
   # 从 Participant 容器 ping Coordinator
   docker-compose exec participant-1 ping coordinator
   ```

2. **检查 gRPC 端口**：
   ```bash
   # 检查 Coordinator gRPC 端口
   docker-compose exec participant-1 nc -zv coordinator 9090
   ```

## 生产环境注意事项

⚠️ **重要**：当前配置仅适用于开发环境，生产环境需要：

1. **安全配置**：
   - 更改 `MPC_KEY_SHARE_ENCRYPTION_KEY` 为强密钥
   - 启用 TLS (`MPC_TLS_ENABLED=true`)
   - 使用安全的数据库连接（SSL）

2. **性能优化**：
   - 调整 PostgreSQL 配置（移除开发环境的性能优化）
   - 配置适当的连接池大小
   - 设置合理的超时和重试策略

3. **监控和日志**：
   - 配置集中式日志收集
   - 设置监控和告警
   - 配置健康检查端点

4. **高可用性**：
   - 部署多个 Coordinator 实例（负载均衡）
   - 配置数据库主从复制
   - 使用 Consul 集群模式

## 下一步

部署完成后，可以：
1. 通过 API 创建密钥分片
2. 执行分布式密钥生成（DKG）
3. 进行阈值签名测试
4. 查看 Consul 中的服务注册情况

参考 [MPC 开发文档](./mpc-development-plan-v2.md) 了解更多开发细节。
