package participant

import (
	"context"
	"encoding/hex"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/pkg/errors"
)

// ProtocolParticipant 协议参与者，处理DKG和签名协议的参与逻辑
type ProtocolParticipant struct {
	service *Service
}

// NewProtocolParticipant 创建协议参与者
func NewProtocolParticipant(service *Service) *ProtocolParticipant {
	return &ProtocolParticipant{
		service: service,
	}
}

// ParticipateKeyGen 参与密钥生成协议
func (p *ProtocolParticipant) ParticipateKeyGen(ctx context.Context, sessionID string, req *protocol.KeyGenRequest) (*KeyShare, error) {
	// 调用协议引擎生成密钥分片
	keyGenResp, err := p.service.protocolEngine.GenerateKeyShare(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key share")
	}

	// 获取当前节点的密钥分片
	// 注意：每个节点只保存自己的分片
	nodeShare, ok := keyGenResp.KeyShares[p.service.nodeID]
	if !ok {
		return nil, errors.Errorf("key share not found for node %s", p.service.nodeID)
	}

	// 保存密钥分片到本地存储
	keyShare := &KeyShare{
		KeyID:  req.KeyID,
		NodeID: p.service.nodeID,
		Share:  nodeShare.Share,
		Index:  nodeShare.Index,
	}

	if err := p.service.StoreKeyShare(ctx, req.KeyID, keyShare); err != nil {
		return nil, errors.Wrap(err, "failed to store key share")
	}

	return keyShare, nil
}

// ParticipateSign 参与签名协议
func (p *ProtocolParticipant) ParticipateSign(ctx context.Context, sessionID string, keyID string, message []byte, nodeIDs []string) (*SignatureShare, error) {
	// 验证密钥分片存在（协议引擎会从keyRecords中获取KeyData）
	_, err := p.service.GetKeyShare(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key share")
	}

	// 准备签名请求
	signReq := &protocol.SignRequest{
		KeyID:      keyID,
		Message:    message,
		MessageHex: "", // 如果message是bytes，MessageHex可以为空
		NodeIDs:    nodeIDs,
	}

	// 调用协议引擎执行签名
	signResp, err := p.service.protocolEngine.ThresholdSign(ctx, sessionID, signReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute threshold signing")
	}

	// tss-lib已经自动聚合，返回完整签名
	sigBytes, _ := hex.DecodeString(signResp.Signature.Hex)
	return &SignatureShare{
		SessionID: sessionID,
		NodeID:    p.service.nodeID,
		Share:     sigBytes,
		Round:     0, // 签名完成后，轮次为0
	}, nil
}
