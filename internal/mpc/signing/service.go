package signing

import (
	"context"
	"encoding/hex"
	"sync"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/pkg/errors"
)

// Service 签名服务
type Service struct {
	keyService     *key.Service
	protocolEngine protocol.Engine
	sessionManager *session.Manager
	nodeDiscovery  *node.Discovery
}

// NewService 创建签名服务
func NewService(
	keyService *key.Service,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
	nodeDiscovery *node.Discovery,
) *Service {
	return &Service{
		keyService:     keyService,
		protocolEngine: protocolEngine,
		sessionManager: sessionManager,
		nodeDiscovery:  nodeDiscovery,
	}
}

// ThresholdSign 阈值签名
func (s *Service) ThresholdSign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// 1. 获取密钥信息
	keyMetadata, err := s.keyService.GetKey(ctx, req.KeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key")
	}

	// 2. 创建签名会话
	signingSession, err := s.sessionManager.CreateSession(ctx, req.KeyID, "gg20", keyMetadata.Threshold, keyMetadata.TotalNodes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signing session")
	}

	// 3. 选择参与节点（达到阈值即可）
	participants, err := s.nodeDiscovery.DiscoverNodes(ctx, node.NodeTypeParticipant, node.NodeStatusActive, keyMetadata.Threshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to discover participants")
	}

	if len(participants) < keyMetadata.Threshold {
		return nil, errors.Errorf("insufficient active nodes: need %d, have %d", keyMetadata.Threshold, len(participants))
	}

	// 选择前 threshold 个节点
	participatingNodes := make([]string, 0, keyMetadata.Threshold)
	for i := 0; i < keyMetadata.Threshold && i < len(participants); i++ {
		participatingNodes = append(participatingNodes, participants[i].NodeID)
	}

	// 更新会话的参与节点
	signingSession.ParticipatingNodes = participatingNodes
	if err := s.sessionManager.UpdateSession(ctx, signingSession); err != nil {
		return nil, errors.Wrap(err, "failed to update session with participating nodes")
	}

	// 4. 准备消息
	var message []byte
	if req.MessageHex != "" {
		var err error
		message, err = hex.DecodeString(req.MessageHex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode message hex")
		}
	} else {
		message = req.Message
	}

	// 5. 准备签名请求
	signReq := &protocol.SignRequest{
		KeyID:      req.KeyID,
		Message:    message,
		MessageHex: hex.EncodeToString(message),
		NodeIDs:    participatingNodes,
	}

	// 6. 执行签名协议
	signResp, err := s.protocolEngine.ThresholdSign(ctx, signingSession.SessionID, signReq)
	if err != nil {
		// 标记会话为失败
		signingSession.Status = "failed"
		s.sessionManager.UpdateSession(ctx, signingSession)
		return nil, errors.Wrap(err, "failed to execute threshold signing")
	}

	// 7. 验证签名
	pubKey := &protocol.PublicKey{
		Hex:   keyMetadata.PublicKey,
		Bytes: []byte(keyMetadata.PublicKey), // 需要从hex解码
	}
	valid, err := s.protocolEngine.VerifySignature(ctx, signResp.Signature, message, pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	}
	if !valid {
		return nil, errors.New("signature verification failed")
	}

	// 8. 完成会话
	signatureHex := signResp.Signature.Hex
	if err := s.sessionManager.CompleteSession(ctx, signingSession.SessionID, signatureHex); err != nil {
		return nil, errors.Wrap(err, "failed to complete session")
	}

	// 9. 构建响应
	response := &SignResponse{
		Signature:          signatureHex,
		KeyID:              req.KeyID,
		PublicKey:          keyMetadata.PublicKey,
		Message:            hex.EncodeToString(message),
		ChainType:          req.ChainType,
		SessionID:          signingSession.SessionID,
		SignedAt:           time.Now().Format(time.RFC3339),
		ParticipatingNodes: participatingNodes,
	}

	return response, nil
}

// BatchSign 批量签名
func (s *Service) BatchSign(ctx context.Context, req *BatchSignRequest) (*BatchSignResponse, error) {
	if len(req.Messages) == 0 {
		return nil, errors.New("no messages to sign")
	}

	// 使用 WaitGroup 和 channel 并发处理
	var wg sync.WaitGroup
	results := make([]*SignResponse, len(req.Messages))
	errors := make([]error, len(req.Messages))
	mu := sync.Mutex{}

	// 并发执行签名
	for i, msgReq := range req.Messages {
		wg.Add(1)
		go func(index int, signReq *SignRequest) {
			defer wg.Done()

			// 设置超时上下文（每个签名最多30秒）
			signCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			resp, err := s.ThresholdSign(signCtx, signReq)
			mu.Lock()
			if err != nil {
				errors[index] = err
			} else {
				results[index] = resp
			}
			mu.Unlock()
		}(i, msgReq)
	}

	// 等待所有签名完成
	wg.Wait()

	// 统计结果
	success := 0
	failed := 0
	validSignatures := make([]*SignResponse, 0, len(req.Messages))

	for i := range req.Messages {
		if errors[i] != nil {
			failed++
		} else if results[i] != nil {
			success++
			validSignatures = append(validSignatures, results[i])
		}
	}

	return &BatchSignResponse{
		Signatures: validSignatures,
		Total:      len(req.Messages),
		Success:    success,
		Failed:     failed,
	}, nil
}

// Verify 验证签名
func (s *Service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	// 1. 解析签名
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode signature hex")
	}

	// 构建签名对象（假设签名格式为 R||S）
	if len(sigBytes) < 64 {
		return nil, errors.New("invalid signature length")
	}

	signature := &protocol.Signature{
		Bytes: sigBytes,
		Hex:   req.Signature,
		R:     sigBytes[:32],
		S:     sigBytes[32:64],
	}

	// 2. 解析公钥
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key hex")
	}

	pubKey := &protocol.PublicKey{
		Bytes: pubKeyBytes,
		Hex:   req.PublicKey,
	}

	// 3. 准备消息
	var message []byte
	if req.MessageHex != "" {
		var err error
		message, err = hex.DecodeString(req.MessageHex)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode message hex")
		}
	} else {
		message = req.Message
	}

	// 4. 验证签名
	valid, err := s.protocolEngine.VerifySignature(ctx, signature, message, pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	}

	// 5. 如果验证成功，生成地址（可选）
	var address string
	if valid && req.ChainType != "" {
		// 这里可以根据链类型生成地址，但需要链适配器
		// 为了简化，暂时返回空地址
		address = ""
	}

	return &VerifyResponse{
		Valid:      valid,
		PublicKey:  req.PublicKey,
		Address:    address,
		VerifiedAt: time.Now().Format(time.RFC3339),
	}, nil
}
