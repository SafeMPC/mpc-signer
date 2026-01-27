package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// VerifyPasskeySignature 验证 WebAuthn Passkey 签名
// publicKeyHex: COSE Key 格式的公钥 (Hex 编码)
// signature: Assertion Signature (Raw bytes)
// authData: Authenticator Data (Raw bytes)
// clientDataJSON: Client Data JSON (Raw bytes)
// expectedChallenge: 期望的 Challenge 字符串 (通常是 Base64URL 编码的 Hash 或随机数)
func VerifyPasskeySignature(publicKeyHex string, signature []byte, authData []byte, clientDataJSON []byte, expectedChallenge string) error {
	// 1. 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}

	pubKey, err := webauthncose.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// 2. 解析 ClientDataJSON
	var clientData protocol.CollectedClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return fmt.Errorf("failed to parse client data: %w", err)
	}

	// 3. 验证 Challenge
	// WebAuthn ClientData 中的 Challenge 是 Base64URL 编码的
	if clientData.Challenge != expectedChallenge {
		// 尝试处理 Padding 差异
		normalizedClient := strings.TrimRight(clientData.Challenge, "=")
		normalizedExpected := strings.TrimRight(expectedChallenge, "=")
		if normalizedClient != normalizedExpected {
			return fmt.Errorf("challenge mismatch: got %s, want %s", clientData.Challenge, expectedChallenge)
		}
	}

	// 4. 解析 AuthenticatorData
	var authenticatorData protocol.AuthenticatorData
	if err := authenticatorData.Unmarshal(authData); err != nil {
		return fmt.Errorf("failed to parse authenticator data: %w", err)
	}

	// 5. 验证 User Present (UP) 位
	if !authenticatorData.Flags.UserPresent() {
		return fmt.Errorf("user not present (UP flag not set)")
	}

	// 6. 验证 User Verified (UV) 位 (可选，视安全策略而定，建议开启)
	// if !authenticatorData.Flags.UserVerified() {
	// 	return fmt.Errorf("user not verified (UV flag not set)")
	// }

	// 7. 构造签名数据: authData || sha256(clientDataJSON)
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData := append(authData, clientDataHash[:]...)

	// 8. 验证签名
	valid, err := webauthncose.VerifySignature(pubKey, signedData, signature)
	if err != nil {
		return fmt.Errorf("error verifying signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// HexToBase64URL 将 Hex 字符串转换为 Base64URL 字符串 (无 Padding)
func HexToBase64URL(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// VerifyAdminPasskey 验证 Admin 的 Passkey
// adminAuth: 需包含字段 PublicKey(string), PasskeySignature([]byte), AuthenticatorData([]byte), ClientDataJson([]byte)
// requestHash: 请求参数的哈希 (Raw bytes)，函数内部转为 Base64URL 用作 expectedChallenge
func VerifyAdminPasskey(adminAuth interface{}, requestHash []byte) error {
	v := reflect.ValueOf(adminAuth)
	if !v.IsValid() {
		return fmt.Errorf("invalid adminAuth")
	}
	// 支持指针
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	// 提取必须字段
	getString := func(name string) (string, error) {
		f := v.FieldByName(name)
		if !f.IsValid() || f.Kind() != reflect.String {
			return "", fmt.Errorf("missing field %s", name)
		}
		return f.String(), nil
	}
	getBytes := func(name string) ([]byte, error) {
		f := v.FieldByName(name)
		if !f.IsValid() || f.Kind() != reflect.Slice || f.Type().Elem().Kind() != reflect.Uint8 {
			return nil, fmt.Errorf("missing field %s", name)
		}
		return f.Bytes(), nil
	}

	publicKey, err := getString("PublicKey")
	if err != nil {
		return err
	}
	signature, err := getBytes("PasskeySignature")
	if err != nil {
		return err
	}
	authData, err := getBytes("AuthenticatorData")
	if err != nil {
		return err
	}
	clientDataJSON, err := getBytes("ClientDataJson")
	if err != nil {
		return err
	}

	expectedChallenge := base64.RawURLEncoding.EncodeToString(requestHash)
	return VerifyPasskeySignature(publicKey, signature, authData, clientDataJSON, expectedChallenge)
}

// VerifyPasskeyMessageSignature 验证 Client 对协议消息的 Passkey 签名（E2E 认证）
// publicKeyHex: Client 的 Passkey 公钥 (Hex 编码，COSE Key Format)
// signature: Client 使用 Passkey 私钥对消息的签名 (Raw bytes)
// sessionID, fromNodeID, toNodeID: 会话和节点信息
// messageData: 协议消息数据 (Raw bytes)
// round, isBroadcast, timestamp: 消息元数据
// 签名数据格式: session_id|from_node_id|to_node_id|message_data_hex|round|is_broadcast|timestamp
func VerifyPasskeyMessageSignature(
	publicKeyHex string,
	signature []byte,
	sessionID, fromNodeID, toNodeID string,
	messageData []byte,
	round int32,
	isBroadcast bool,
	timestamp string,
) error {
	// 1. 解析公钥
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}

	pubKey, err := webauthncose.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// 2. 构建待签名数据（与 Client 端保持一致）
	data := fmt.Sprintf("%s|%s|%s|%x|%d|%v|%s",
		sessionID, fromNodeID, toNodeID, messageData, round, isBroadcast, timestamp)

	// 3. 计算数据的 SHA256 哈希（Passkey 通常对哈希签名）
	dataHash := sha256.Sum256([]byte(data))

	// 4. 验证签名
	valid, err := webauthncose.VerifySignature(pubKey, dataHash[:], signature)
	if err != nil {
		return fmt.Errorf("error verifying signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
