# tss-lib 集成指南

## 当前状态

已添加 `tss-lib` 依赖并创建了生产级实现框架，但存在依赖版本冲突需要解决。

## 依赖问题

`tss-lib v1.5.0` 需要 `github.com/btcsuite/btcd/btcec`，但当前项目的 `btcd v0.25.0` 不包含此包（该包在新版本中已移除）。

## 解决方案

### 方案1：使用兼容的 btcd 版本（推荐）

```bash
# 降级 btcd 到兼容版本
go get github.com/btcsuite/btcd@v0.23.4
go mod tidy
```

### 方案2：使用 tss-lib 的 fork 版本

查找已更新依赖的 tss-lib fork，或自行 fork 并更新依赖。

### 方案3：等待 tss-lib 更新

关注 tss-lib 的更新，等待其适配新版本的 btcd。

## 已实现的代码结构

1. **`internal/mpc/protocol/gg18_tss.go`** - tss-lib 适配层
   - `tssPartyManager` - 管理 Party 实例和消息路由
   - `executeKeygen` - 执行真正的 DKG 协议
   - `executeSigning` - 执行真正的阈值签名协议

2. **`internal/mpc/protocol/gg18.go`** - 更新的 GG18 协议实现
   - 移除了私钥重构逻辑
   - 使用 tss-lib 的 `LocalPartySaveData` 存储密钥数据
   - 通过 `tssPartyManager` 执行真正的 MPC 协议

## 下一步

1. 解决依赖冲突（选择上述方案之一）
2. 实现消息路由机制（集成到 gRPC 通信层）
3. 完善 `convertTSSKeyData` 函数（正确提取分片数据）
4. 添加错误处理和重试逻辑
5. 编写集成测试

## 关键改进

✅ **已移除**：私钥重构逻辑（`reconstructSecret`）  
✅ **已实现**：基于 tss-lib 的真实 MPC 协议框架  
✅ **已添加**：消息路由接口，支持节点间通信  
⚠️ **待解决**：依赖版本冲突  
⚠️ **待实现**：完整的消息路由集成

