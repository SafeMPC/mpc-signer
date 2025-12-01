package participant

import (
	"context"

	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/pkg/errors"
)

// Service Participant服务
type Service struct {
	nodeID          string
	keyShareStorage storage.KeyShareStorage
	protocolEngine  protocol.Engine
}

// NewService 创建Participant服务
func NewService(
	nodeID string,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
) *Service {
	return &Service{
		nodeID:          nodeID,
		keyShareStorage: keyShareStorage,
		protocolEngine:  protocolEngine,
	}
}

// ParticipateKeyGen 参与密钥生成
func (s *Service) ParticipateKeyGen(ctx context.Context, sessionID string, req *protocol.KeyGenRequest) (*KeyShare, error) {
	participant := NewProtocolParticipant(s)
	return participant.ParticipateKeyGen(ctx, sessionID, req)
}

// ParticipateSign 参与签名
func (s *Service) ParticipateSign(ctx context.Context, sessionID string, keyID string, msg []byte, nodeIDs []string) (*SignatureShare, error) {
	participant := NewProtocolParticipant(s)
	return participant.ParticipateSign(ctx, sessionID, keyID, msg, nodeIDs)
}

// StoreKeyShare 存储密钥分片
func (s *Service) StoreKeyShare(ctx context.Context, keyID string, share *KeyShare) error {
	if err := s.keyShareStorage.StoreKeyShare(ctx, keyID, share.NodeID, share.Share); err != nil {
		return errors.Wrap(err, "failed to store key share")
	}
	return nil
}

// GetKeyShare 获取密钥分片
func (s *Service) GetKeyShare(ctx context.Context, keyID string) (*KeyShare, error) {
	share, err := s.keyShareStorage.GetKeyShare(ctx, keyID, s.nodeID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key share")
	}

	return &KeyShare{
		KeyID:  keyID,
		NodeID: s.nodeID,
		Share:  share,
	}, nil
}
