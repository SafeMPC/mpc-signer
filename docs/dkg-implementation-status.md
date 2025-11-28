# DKG 实现状态分析

## 当前状态：**未完成** ⚠️

虽然已经集成了 tss-lib 并搭建了基本框架，但**缺少关键的消息处理逻辑**。

## ✅ 已完成的部分

### 1. 协议框架搭建
- ✅ 集成了 `github.com/kashguard/tss-lib`
- ✅ 创建了 `tssPartyManager` 管理 Party 实例
- ✅ 实现了 `executeKeygen` 方法框架
- ✅ 使用 tss-lib 的 `keygen.NewLocalParty` 创建协议实例
- ✅ 设置了正确的参数（曲线、阈值、节点数等）
- ✅ 启动了协议执行

### 2. 消息发送
- ✅ 实现了消息路由函数接口
- ✅ 从 `outCh` 接收 tss-lib 生成的消息
- ✅ 通过 `messageRouter` 发送消息到其他节点

### 3. 数据转换
- ✅ 实现了 `convertTSSKeyData` 将 tss-lib 数据转换为内部格式
- ✅ 实现了公钥提取和序列化

## ❌ 缺失的关键部分

### 1. **消息接收和处理**（最关键）

**问题**：当前实现只能**发送**消息，但无法**接收和处理**来自其他节点的消息。

**需要实现**：
```go
// 需要添加的方法
func (m *tssPartyManager) ProcessIncomingMessage(
    ctx context.Context,
    keyID string,  // 或 sessionID
    fromNodeID string,
    msgBytes []byte,
) error {
    // 1. 找到对应的 Party 实例
    party, ok := m.activeKeygen[keyID]
    if !ok {
        return errors.New("no active keygen session")
    }
    
    // 2. 反序列化消息
    msg, err := tss.ParseWireMessage(msgBytes)
    if err != nil {
        return errors.Wrap(err, "parse message")
    }
    
    // 3. 将消息传递给 Party
    _, err = party.UpdateFromBytes(msg.WireBytes(), msg.GetFrom(), msg.IsBroadcast())
    if err != nil {
        return errors.Wrap(err, "update party with message")
    }
    
    return nil
}
```

### 2. **消息序列化/反序列化**

**问题**：tss-lib 的消息需要序列化后通过网络传输。

**需要实现**：
```go
// 序列化消息用于网络传输
func serializeMessage(msg tss.Message) ([]byte, error) {
    return msg.WireBytes(), nil
}

// 反序列化接收到的消息
func deserializeMessage(msgBytes []byte) (tss.ParsedMessage, error) {
    return tss.ParseWireMessage(msgBytes)
}
```

### 3. **多节点协调机制**

**问题**：当前实现假设所有节点都在同一个进程中，但实际上需要：
- 跨节点的消息传输（gRPC/HTTP）
- 节点发现和注册
- 会话管理（确保所有节点同时参与）

**需要实现**：
- 在 `coordinator` 服务中协调所有节点
- 在 `participant` 服务中接收和处理 DKG 请求
- 消息队列或事件总线来管理消息流

### 4. **错误处理和超时**

**问题**：当前有超时机制，但缺少：
- 节点故障处理
- 消息重传机制
- 协议中断恢复

## 📋 完成 DKG 需要的步骤

### 步骤 1：实现消息接收处理（优先级：高）

在 `gg18_tss.go` 中添加：

```go
// ProcessIncomingKeygenMessage 处理接收到的 DKG 消息
func (m *tssPartyManager) ProcessIncomingKeygenMessage(
    ctx context.Context,
    keyID string,
    fromNodeID string,
    msgBytes []byte,
) error {
    m.mu.RLock()
    party, ok := m.activeKeygen[keyID]
    m.mu.RUnlock()
    
    if !ok {
        return errors.Errorf("no active keygen session for keyID: %s", keyID)
    }
    
    // 解析消息
    msg, err := tss.ParseWireMessage(msgBytes)
    if err != nil {
        return errors.Wrap(err, "parse wire message")
    }
    
    // 更新 Party 状态
    _, err = party.UpdateFromBytes(msg.WireBytes(), msg.GetFrom(), msg.IsBroadcast())
    if err != nil {
        return errors.Wrap(err, "update party with incoming message")
    }
    
    return nil
}
```

### 步骤 2：在 Coordinator 中实现消息路由（优先级：高）

在 `internal/mpc/coordinator/service.go` 中：

```go
// 实现消息路由，将消息发送到对应的 Participant 节点
func (s *Service) routeDKGMessage(ctx context.Context, targetNodeID string, msg tss.Message) error {
    // 1. 序列化消息
    msgBytes := msg.WireBytes()
    
    // 2. 通过 gRPC 发送到目标节点
    participant, err := s.nodeManager.GetNode(ctx, targetNodeID)
    if err != nil {
        return errors.Wrap(err, "get participant node")
    }
    
    // 3. 调用 Participant 的 gRPC 接口
    return s.grpcClient.SendDKGMessage(ctx, participant.Endpoint, msgBytes)
}
```

### 步骤 3：在 Participant 中实现消息接收（优先级：高）

在 `internal/mpc/participant/service.go` 中：

```go
// ReceiveDKGMessage 接收来自 Coordinator 或其他节点的 DKG 消息
func (s *Service) ReceiveDKGMessage(ctx context.Context, keyID string, fromNodeID string, msgBytes []byte) error {
    // 调用协议引擎处理消息
    return s.protocolEngine.ProcessIncomingKeygenMessage(ctx, keyID, fromNodeID, msgBytes)
}
```

### 步骤 4：实现完整的 DKG 流程（优先级：中）

在 `internal/mpc/key/dkg.go` 中：

```go
// ExecuteDKG 需要协调所有节点：
// 1. 通知所有节点开始 DKG
// 2. 等待所有节点完成
// 3. 验证结果
```

## 🎯 总结

**当前进度**：约 **40%**

- ✅ 协议框架：100%
- ✅ 消息发送：100%
- ❌ 消息接收：0%
- ❌ 多节点协调：0%
- ❌ 错误处理：30%

**要完成 DKG 实现，最关键的缺失是消息接收和处理逻辑**。一旦实现了消息接收，DKG 就可以在多个节点之间真正运行起来。

## 📝 下一步行动

1. **立即**：实现 `ProcessIncomingKeygenMessage` 方法
2. **立即**：在 Coordinator 中实现消息路由
3. **立即**：在 Participant 中实现消息接收
4. **后续**：添加集成测试验证多节点 DKG
5. **后续**：实现错误处理和重试机制

