package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/kashguard/tss-lib/common"
	"github.com/kashguard/tss-lib/ecdsa/keygen"
	"github.com/kashguard/tss-lib/ecdsa/signing"
	eddsaKeygen "github.com/kashguard/tss-lib/eddsa/keygen"
	eddsaSigning "github.com/kashguard/tss-lib/eddsa/signing"
	"github.com/kashguard/tss-lib/tss"
	"github.com/pkg/errors"
)

// tssPartyManager 管理 tss-lib 的 Party 实例和消息路由（通用适配层，供 GG18/GG20/FROST 使用）
type tssPartyManager struct {
	mu sync.RWMutex

	// 节点到 PartyID 的映射
	nodeIDToPartyID map[string]*tss.PartyID
	partyIDToNodeID map[string]string

	// 当前活跃的协议实例（ECDSA - GG18/GG20）
	activeKeygen  map[string]*keygen.LocalParty
	activeSigning map[string]*signing.LocalParty

	// 当前活跃的协议实例（EdDSA - FROST）
	activeEdDSAKeygen  map[string]*eddsaKeygen.LocalParty
	activeEdDSASigning map[string]*eddsaSigning.LocalParty

	// 消息路由：从 tss-lib 消息到节点通信
	messageRouter func(nodeID string, msg tss.Message) error
}

func newTSSPartyManager(messageRouter func(nodeID string, msg tss.Message) error) *tssPartyManager {
	return &tssPartyManager{
		nodeIDToPartyID:    make(map[string]*tss.PartyID),
		partyIDToNodeID:    make(map[string]string),
		activeKeygen:       make(map[string]*keygen.LocalParty),
		activeSigning:      make(map[string]*signing.LocalParty),
		activeEdDSAKeygen:  make(map[string]*eddsaKeygen.LocalParty),
		activeEdDSASigning: make(map[string]*eddsaSigning.LocalParty),
		messageRouter:      messageRouter,
	}
}

// setupPartyIDs 为节点创建 PartyID
func (m *tssPartyManager) setupPartyIDs(nodeIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, nodeID := range nodeIDs {
		if _, exists := m.nodeIDToPartyID[nodeID]; exists {
			continue
		}

		// 使用节点ID的哈希作为唯一密钥
		hash := sha256.Sum256([]byte(nodeID))
		uniqueKey := new(big.Int).SetBytes(hash[:])

		partyID := tss.NewPartyID(nodeID, nodeID, uniqueKey)
		m.nodeIDToPartyID[nodeID] = partyID
		m.partyIDToNodeID[partyID.Id] = nodeID
	}

	return nil
}

// getPartyIDs 获取排序后的 PartyID 列表
func (m *tssPartyManager) getPartyIDs(nodeIDs []string) (tss.SortedPartyIDs, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	parties := make([]*tss.PartyID, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		partyID, ok := m.nodeIDToPartyID[nodeID]
		if !ok {
			return nil, errors.Errorf("party ID not found for node: %s", nodeID)
		}
		parties = append(parties, partyID)
	}

	return tss.SortPartyIDs(parties), nil
}

// getPartyID 获取指定节点的 PartyID（用于外部访问）
func (m *tssPartyManager) getPartyID(nodeID string) (*tss.PartyID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	partyID, ok := m.nodeIDToPartyID[nodeID]
	return partyID, ok
}

// getNodeID 根据 PartyID 获取节点ID（用于外部访问）
func (m *tssPartyManager) getNodeID(partyID string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nodeID, ok := m.partyIDToNodeID[partyID]
	return nodeID, ok
}

// executeKeygen 执行真正的 DKG 协议
func (m *tssPartyManager) executeKeygen(
	ctx context.Context,
	keyID string,
	nodeIDs []string,
	threshold int,
	thisNodeID string,
) (*keygen.LocalPartySaveData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.S256(), ctxTSS, thisPartyID, len(parties), threshold)

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *keygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 LocalParty
	party := keygen.NewLocalParty(params, outCh, endCh)

	m.mu.Lock()
	// 类型断言为 *keygen.LocalParty
	if localParty, ok := party.(*keygen.LocalParty); ok {
		m.activeKeygen[keyID] = localParty
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 处理消息和结果
	timeout := time.NewTimer(5 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.New("keygen timeout")
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter != nil {
				targetNodeID := m.partyIDToNodeID[msg.GetTo()[0].Id]
				if err := m.messageRouter(targetNodeID, msg); err != nil {
					return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
				}
			}
		case saveData := <-endCh:
			m.mu.Lock()
			delete(m.activeKeygen, keyID)
			m.mu.Unlock()
			if saveData == nil {
				return nil, errors.New("keygen returned nil save data")
			}
			return saveData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeKeygen, keyID)
			m.mu.Unlock()
			return nil, errors.Wrap(err, "keygen error")
		}
	}
}

// SigningOptions 签名执行选项
type SigningOptions struct {
	// Timeout 超时时间（默认 2 分钟）
	Timeout time.Duration
	// EnableIdentifiableAbort 是否支持可识别的中止（GG20 特性）
	EnableIdentifiableAbort bool
	// ProtocolName 协议名称（用于错误消息）
	ProtocolName string
}

// DefaultSigningOptions 返回默认的签名选项（GG18）
func DefaultSigningOptions() SigningOptions {
	return SigningOptions{
		Timeout:                 2 * time.Minute,
		EnableIdentifiableAbort: false,
		ProtocolName:            "GG18",
	}
}

// GG20SigningOptions 返回 GG20 的签名选项
func GG20SigningOptions() SigningOptions {
	return SigningOptions{
		Timeout:                 1 * time.Minute,
		EnableIdentifiableAbort: true,
		ProtocolName:            "GG20",
	}
}

// executeSigning 执行真正的阈值签名协议（通用实现，支持 GG18/GG20）
func (m *tssPartyManager) executeSigning(
	ctx context.Context,
	sessionID string,
	keyID string,
	message []byte,
	nodeIDs []string,
	thisNodeID string,
	keyData *keygen.LocalPartySaveData,
	opts SigningOptions,
) (*common.SignatureData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.getPartyID(thisNodeID)
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.S256(), ctxTSS, thisPartyID, len(parties), len(parties)-1)

	// 计算消息哈希
	hash := sha256.Sum256(message)
	msgBigInt := new(big.Int).SetBytes(hash[:])

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 LocalParty
	party := signing.NewLocalParty(msgBigInt, params, *keyData, outCh, endCh)

	m.mu.Lock()
	// 类型断言为 *signing.LocalParty
	if localParty, ok := party.(*signing.LocalParty); ok {
		m.activeSigning[sessionID] = localParty
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 处理消息和结果
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute // 默认超时
	}
	if opts.ProtocolName == "" {
		opts.ProtocolName = "TSS"
	}
	timeout := time.NewTimer(opts.Timeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.Errorf("%s signing timeout", opts.ProtocolName)
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter != nil {
				for _, to := range msg.GetTo() {
					targetNodeID, ok := m.getNodeID(to.Id)
					if !ok {
						return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
					}
					if err := m.messageRouter(targetNodeID, msg); err != nil {
						return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
					}
				}
			}
		case sigData := <-endCh:
			m.mu.Lock()
			delete(m.activeSigning, sessionID)
			m.mu.Unlock()
			if sigData == nil {
				return nil, errors.Errorf("%s signing returned nil signature data", opts.ProtocolName)
			}
			return sigData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeSigning, sessionID)
			m.mu.Unlock()
			// 如果支持可识别的中止，可以识别恶意节点
			if opts.EnableIdentifiableAbort && err.Culprits() != nil {
				return nil, errors.Wrapf(err, "%s signing error (identifiable abort: %v)", opts.ProtocolName, err.Culprits())
			}
			return nil, errors.Wrapf(err, "%s signing error", opts.ProtocolName)
		}
	}
}

// convertTSSKeyData 将 tss-lib 的保存数据转换为我们的 KeyShare 格式
func convertTSSKeyData(
	keyID string,
	saveData *keygen.LocalPartySaveData,
	nodeIDs []string,
) (map[string]*KeyShare, *PublicKey, error) {
	keyShares := make(map[string]*KeyShare)

	// 获取公钥（通过 ECDSA 公钥转换）
	ecdsaPubKey := saveData.ECDSAPub.ToECDSAPubKey()
	if ecdsaPubKey == nil {
		return nil, nil, errors.New("failed to convert ECPoint to ECDSA public key")
	}

	// 将 ECDSA 公钥序列化为压缩格式
	// secp256k1 压缩公钥：0x02/0x03 + 32字节 X坐标
	var pubKeyBytes []byte
	if ecdsaPubKey.Y.Bit(0) == 0 {
		pubKeyBytes = append([]byte{0x02}, ecdsaPubKey.X.Bytes()...)
	} else {
		pubKeyBytes = append([]byte{0x03}, ecdsaPubKey.X.Bytes()...)
	}
	// 确保 X 坐标是 32 字节
	if len(ecdsaPubKey.X.Bytes()) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(ecdsaPubKey.X.Bytes()):], ecdsaPubKey.X.Bytes())
		if ecdsaPubKey.Y.Bit(0) == 0 {
			pubKeyBytes = append([]byte{0x02}, padded...)
		} else {
			pubKeyBytes = append([]byte{0x03}, padded...)
		}
	}
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	publicKey := &PublicKey{
		Bytes: pubKeyBytes,
		Hex:   pubKeyHex,
	}

	// 注意：tss-lib 不直接暴露私钥分片，每个节点只保存自己的分片
	// 这里我们需要从 saveData 中提取分片信息
	// 实际实现中，每个节点应该只保存自己的 saveData，而不是所有节点的

	// 为每个节点创建 KeyShare（实际应该从各自的 saveData 中获取）
	for idx, nodeID := range nodeIDs {
		// 这里需要根据实际的 tss-lib 数据结构来提取分片
		// 由于 tss-lib 的设计，每个节点只知道自己分片的索引
		shareID := fmt.Sprintf("%s-%02d", keyID, idx+1)

		// 注意：实际的分片数据应该从 saveData 中提取
		// 这里只是示例，实际需要根据 tss-lib 的 LocalPartySaveData 结构来提取
		keyShares[nodeID] = &KeyShare{
			ShareID: shareID,
			NodeID:  nodeID,
			Share:   nil, // 实际应该从 saveData 中提取
			Index:   idx + 1,
		}
	}

	return keyShares, publicKey, nil
}

// convertTSSSignature 将 tss-lib 的签名数据转换为我们的 Signature 格式
func convertTSSSignature(sigData *common.SignatureData) (*Signature, error) {
	if sigData == nil {
		return nil, errors.New("signature data is nil")
	}

	// tss-lib 的签名是 (R, S) 格式，已经是 []byte
	rBytes := sigData.R
	sBytes := sigData.S

	// 填充到 32 字节
	rPadded := padScalarBytes(rBytes)
	sPadded := padScalarBytes(sBytes)

	// 构建 DER 编码的签名
	der := buildDERSignature(rPadded, sPadded)

	return &Signature{
		R:     rPadded,
		S:     sPadded,
		Bytes: der,
		Hex:   hex.EncodeToString(der),
	}, nil
}

func buildDERSignature(r, s []byte) []byte {
	// 简化的 DER 编码实现
	// 实际应该使用标准的 DER 编码库
	der := make([]byte, 0, 70)
	der = append(der, 0x30) // SEQUENCE
	der = append(der, byte(len(r)+len(s)+4))
	der = append(der, 0x02) // INTEGER
	der = append(der, byte(len(r)))
	der = append(der, r...)
	der = append(der, 0x02) // INTEGER
	der = append(der, byte(len(s)))
	der = append(der, s...)
	return der
}

func padScalarBytes(src []byte) []byte {
	const size = 32
	if len(src) >= size {
		return append([]byte(nil), src[len(src)-size:]...)
	}
	dst := make([]byte, size)
	copy(dst[size-len(src):], src)
	return dst
}

// executeEdDSAKeygen 执行 EdDSA DKG 协议（用于 FROST）
func (m *tssPartyManager) executeEdDSAKeygen(
	ctx context.Context,
	keyID string,
	nodeIDs []string,
	threshold int,
	thisNodeID string,
) (*eddsaKeygen.LocalPartySaveData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.Edwards(), ctxTSS, thisPartyID, len(parties), threshold)

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *eddsaKeygen.LocalPartySaveData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 EdDSA LocalParty
	party := eddsaKeygen.NewLocalParty(params, outCh, endCh)

	m.mu.Lock()
	if localParty, ok := party.(*eddsaKeygen.LocalParty); ok {
		m.activeEdDSAKeygen[keyID] = localParty
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 处理消息和结果
	timeout := time.NewTimer(5 * time.Minute)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.New("EdDSA keygen timeout")
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter != nil {
				for _, to := range msg.GetTo() {
					targetNodeID, ok := m.getNodeID(to.Id)
					if !ok {
						return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
					}
					if err := m.messageRouter(targetNodeID, msg); err != nil {
						return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
					}
				}
			}
		case saveData := <-endCh:
			m.mu.Lock()
			delete(m.activeEdDSAKeygen, keyID)
			m.mu.Unlock()
			if saveData == nil {
				return nil, errors.New("EdDSA keygen returned nil save data")
			}
			return saveData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeEdDSAKeygen, keyID)
			m.mu.Unlock()
			return nil, errors.Wrap(err, "EdDSA keygen error")
		}
	}
}

// executeEdDSASigning 执行 EdDSA 签名协议（用于 FROST，2 轮）
func (m *tssPartyManager) executeEdDSASigning(
	ctx context.Context,
	sessionID string,
	keyID string,
	message []byte,
	nodeIDs []string,
	thisNodeID string,
	keyData *eddsaKeygen.LocalPartySaveData,
	opts SigningOptions,
) (*common.SignatureData, error) {
	if err := m.setupPartyIDs(nodeIDs); err != nil {
		return nil, errors.Wrap(err, "setup party IDs")
	}

	parties, err := m.getPartyIDs(nodeIDs)
	if err != nil {
		return nil, errors.Wrap(err, "get party IDs")
	}

	thisPartyID, ok := m.nodeIDToPartyID[thisNodeID]
	if !ok {
		return nil, errors.Errorf("this node ID not found: %s", thisNodeID)
	}

	ctxTSS := tss.NewPeerContext(parties)
	params := tss.NewParameters(tss.Edwards(), ctxTSS, thisPartyID, len(parties), len(parties)-1)

	// 计算消息哈希
	hash := sha256.Sum256(message)
	msgBigInt := new(big.Int).SetBytes(hash[:])

	// 创建消息通道
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan *common.SignatureData, 1)
	errCh := make(chan *tss.Error, 1)

	// 创建 EdDSA LocalParty（FROST 使用 EdDSA signing，2 轮）
	party := eddsaSigning.NewLocalParty(msgBigInt, params, *keyData, outCh, endCh)

	m.mu.Lock()
	if localParty, ok := party.(*eddsaSigning.LocalParty); ok {
		m.activeEdDSASigning[sessionID] = localParty
	}
	m.mu.Unlock()

	// 启动协议
	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	// 处理消息和结果（FROST 2 轮，超时时间可以更短）
	timeout := time.NewTimer(opts.Timeout)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, errors.Errorf("%s signing timeout", opts.ProtocolName)
		case msg := <-outCh:
			// 路由消息到其他节点
			if m.messageRouter != nil {
				for _, to := range msg.GetTo() {
					targetNodeID, ok := m.getNodeID(to.Id)
					if !ok {
						return nil, errors.Errorf("party ID to node ID mapping not found: %s", to.Id)
					}
					if err := m.messageRouter(targetNodeID, msg); err != nil {
						return nil, errors.Wrapf(err, "route message to node %s", targetNodeID)
					}
				}
			}
		case sigData := <-endCh:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			m.mu.Unlock()
			if sigData == nil {
				return nil, errors.Errorf("%s signing returned nil signature data", opts.ProtocolName)
			}
			return sigData, nil
		case err := <-errCh:
			m.mu.Lock()
			delete(m.activeEdDSASigning, sessionID)
			m.mu.Unlock()
			if opts.EnableIdentifiableAbort && err.Culprits() != nil {
				return nil, errors.Wrapf(err, "%s signing error (identifiable abort: %v)", opts.ProtocolName, err.Culprits())
			}
			return nil, errors.Wrapf(err, "%s signing error", opts.ProtocolName)
		}
	}
}

// FROSTSigningOptions 返回 FROST 的签名选项
func FROSTSigningOptions() SigningOptions {
	return SigningOptions{
		Timeout:                 1 * time.Minute, // FROST 2 轮，超时时间更短
		EnableIdentifiableAbort: false,           // FROST 不支持可识别的中止
		ProtocolName:            "FROST",
	}
}
