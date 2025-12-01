package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/kashguard/tss-lib/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMessageRouter 模拟消息路由函数（用于测试）
func mockMessageRouter(nodeID string, msg tss.Message) error {
	// 在单元测试中，消息路由只是记录，不实际发送
	return nil
}

func TestNewGG18Protocol(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	assert.NotNil(t, protocol)
	assert.Equal(t, "secp256k1", protocol.GetCurve())
	assert.Equal(t, []string{"gg18"}, protocol.SupportedProtocols())
	assert.Equal(t, "gg18", protocol.DefaultProtocol())
}

func TestValidateKeyGenRequest(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	tests := []struct {
		name    string
		req     *KeyGenRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: &KeyGenRequest{
				Algorithm:  "ECDSA",
				Curve:      "secp256k1",
				Threshold:  2,
				TotalNodes: 3,
				NodeIDs:    []string{"node-1", "node-2", "node-3"},
			},
			wantErr: false,
		},
		{
			name: "unsupported algorithm",
			req: &KeyGenRequest{
				Algorithm:  "RSA",
				Curve:      "secp256k1",
				Threshold:  2,
				TotalNodes: 3,
			},
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
		{
			name: "unsupported curve",
			req: &KeyGenRequest{
				Algorithm:  "ECDSA",
				Curve:      "P256",
				Threshold:  2,
				TotalNodes: 3,
			},
			wantErr: true,
			errMsg:  "unsupported curve",
		},
		{
			name: "threshold too low",
			req: &KeyGenRequest{
				Algorithm:  "ECDSA",
				Curve:      "secp256k1",
				Threshold:  1,
				TotalNodes: 3,
			},
			wantErr: true,
			errMsg:  "threshold must be at least 2",
		},
		{
			name: "total nodes less than threshold",
			req: &KeyGenRequest{
				Algorithm:  "ECDSA",
				Curve:      "secp256k1",
				Threshold:  3,
				TotalNodes: 2,
			},
			wantErr: true,
			errMsg:  "total nodes must be at least threshold",
		},
		{
			name: "node IDs count mismatch",
			req: &KeyGenRequest{
				Algorithm:  "ECDSA",
				Curve:      "secp256k1",
				Threshold:  2,
				TotalNodes: 3,
				NodeIDs:    []string{"node-1", "node-2"},
			},
			wantErr: true,
			errMsg:  "node IDs count mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.ValidateKeyGenRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateSignRequest(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	tests := []struct {
		name    string
		req     *SignRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with message",
			req: &SignRequest{
				KeyID:   "key-1",
				Message: []byte("hello world"),
				NodeIDs: []string{"node-1", "node-2"},
			},
			wantErr: false,
		},
		{
			name: "valid request with message hex",
			req: &SignRequest{
				KeyID:      "key-1",
				MessageHex: "0x68656c6c6f20776f726c64",
				NodeIDs:    []string{"node-1", "node-2"},
			},
			wantErr: false,
		},
		{
			name: "missing key ID",
			req: &SignRequest{
				Message: []byte("hello"),
				NodeIDs: []string{"node-1"},
			},
			wantErr: true,
			errMsg:  "key ID is required",
		},
		{
			name: "missing message",
			req: &SignRequest{
				KeyID:   "key-1",
				NodeIDs: []string{"node-1"},
			},
			wantErr: true,
			errMsg:  "message is required",
		},
		{
			name: "missing node IDs",
			req: &SignRequest{
				KeyID:   "key-1",
				Message: []byte("hello"),
			},
			wantErr: true,
			errMsg:  "node IDs are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.ValidateSignRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeNodeIDs(t *testing.T) {
	tests := []struct {
		name      string
		ids       []string
		total     int
		wantIDs   []string
		wantError bool
	}{
		{
			name:      "auto generate node IDs",
			ids:       nil,
			total:     3,
			wantIDs:   []string{"node-01", "node-02", "node-03"},
			wantError: false,
		},
		{
			name:      "use provided node IDs",
			ids:       []string{"node-a", "node-b", "node-c"},
			total:     3,
			wantIDs:   []string{"node-a", "node-b", "node-c"},
			wantError: false,
		},
		{
			name:      "count mismatch",
			ids:       []string{"node-a", "node-b"},
			total:     3,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := normalizeNodeIDs(tt.ids, tt.total)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantIDs, result)
			}
		})
	}
}

func TestResolveMessagePayload(t *testing.T) {
	tests := []struct {
		name      string
		req       *SignRequest
		wantBytes []byte
		wantError bool
	}{
		{
			name: "message from bytes",
			req: &SignRequest{
				Message: []byte("hello world"),
			},
			wantBytes: []byte("hello world"),
			wantError: false,
		},
		{
			name: "message from hex with 0x prefix",
			req: &SignRequest{
				MessageHex: "0x68656c6c6f20776f726c64",
			},
			wantBytes: []byte("hello world"),
			wantError: false,
		},
		{
			name: "message from hex without 0x prefix",
			req: &SignRequest{
				MessageHex: "68656c6c6f20776f726c64",
			},
			wantBytes: []byte("hello world"),
			wantError: false,
		},
		{
			name: "empty message",
			req: &SignRequest{
				Message:    nil,
				MessageHex: "",
			},
			wantError: true,
		},
		{
			name: "invalid hex",
			req: &SignRequest{
				MessageHex: "0xinvalid",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveMessagePayload(tt.req)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantBytes, result)
			}
		})
	}
}

func TestVerifyECDSASignature(t *testing.T) {
	// 生成测试密钥对
	privKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()

	// 准备消息
	message := []byte("test message")
	hash := sha256.Sum256(message)

	// 生成签名
	signature := ecdsa.Sign(privKey, hash[:])

	// 序列化公钥和签名
	pubKeyBytes := pubKey.SerializeCompressed()
	sigBytes := signature.Serialize()

	// 从 DER 编码的签名中解析 R 和 S（用于测试）
	// DER 格式: 0x30 [总长度] 0x02 [R长度] [R值] 0x02 [S长度] [S值]
	parsedSig, err := ecdsa.ParseDERSignature(sigBytes)
	require.NoError(t, err)

	// 验证签名以确保它是有效的
	valid := parsedSig.Verify(hash[:], pubKey)
	require.True(t, valid, "generated signature should be valid")

	// 为了测试，我们从 DER 格式手动解析 R 和 S
	// 这是一个简化的解析，仅用于测试
	// 实际使用中，R 和 S 应该从 tss-lib 的签名数据中获取
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	// 由于我们无法直接访问 R 和 S，我们使用占位符
	// 在实际的 MPC 场景中，R 和 S 会从 tss-lib 的 SignatureData 中获取
	copy(rBytes[32-len(hash[:16]):], hash[:16]) // 占位符
	copy(sBytes[32-len(hash[16:]):], hash[16:]) // 占位符

	// 创建测试用的公钥和签名对象
	testPubKey := &PublicKey{
		Bytes: pubKeyBytes,
		Hex:   hex.EncodeToString(pubKeyBytes),
	}
	testSig := &Signature{
		R:     rBytes,
		S:     sBytes,
		Bytes: sigBytes,
		Hex:   hex.EncodeToString(sigBytes),
	}

	tests := []struct {
		name      string
		sig       *Signature
		msg       []byte
		pubKey    *PublicKey
		wantValid bool
		wantError bool
	}{
		{
			name:      "valid signature",
			sig:       testSig,
			msg:       message,
			pubKey:    testPubKey,
			wantValid: true,
			wantError: false,
		},
		{
			name:      "wrong message",
			sig:       testSig,
			msg:       []byte("wrong message"),
			pubKey:    testPubKey,
			wantValid: false,
			wantError: false,
		},
		{
			name:      "nil signature",
			sig:       nil,
			msg:       message,
			pubKey:    testPubKey,
			wantValid: false,
			wantError: true,
		},
		{
			name: "empty signature bytes",
			sig: &Signature{
				Bytes: nil,
			},
			msg:       message,
			pubKey:    testPubKey,
			wantValid: false,
			wantError: true,
		},
		{
			name:      "empty message",
			sig:       testSig,
			msg:       nil,
			pubKey:    testPubKey,
			wantValid: false,
			wantError: true,
		},
		{
			name:      "nil public key",
			sig:       testSig,
			msg:       message,
			pubKey:    nil,
			wantValid: false,
			wantError: true,
		},
		{
			name: "invalid public key",
			sig:  testSig,
			msg:  message,
			pubKey: &PublicKey{
				Bytes: []byte("invalid"),
			},
			wantValid: false,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := verifyECDSASignature(tt.sig, tt.msg, tt.pubKey)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantValid, valid)
			}
		})
	}
}

func TestGenerateKeyID(t *testing.T) {
	id1 := generateKeyID()
	id2 := generateKeyID()

	// 确保生成的 ID 不为空
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)

	// 确保每次生成的 ID 不同（基于时间戳）
	assert.NotEqual(t, id1, id2)

	// 确保格式正确（以 "key-" 开头）
	assert.Contains(t, id1, "key-")
}

func TestRotateKey(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	ctx := context.Background()
	err := protocol.RotateKey(ctx, "key-1")

	// RotateKey 目前未实现，应该返回错误
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestGetKeyRecord(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	// 测试获取不存在的密钥
	_, ok := protocol.getKeyRecord("non-existent")
	assert.False(t, ok)
}

func TestGG18Protocol_GetCurve(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	assert.Equal(t, "secp256k1", protocol.GetCurve())
}

func TestGG18Protocol_SupportedProtocols(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	protocols := protocol.SupportedProtocols()
	assert.Equal(t, []string{"gg18"}, protocols)
}

func TestGG18Protocol_DefaultProtocol(t *testing.T) {
	protocol := NewGG18Protocol("secp256k1", "node-1", mockMessageRouter)

	assert.Equal(t, "gg18", protocol.DefaultProtocol())
}
