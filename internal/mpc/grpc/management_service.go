package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/kashguard/go-mpc-infra/internal/auth"
	"github.com/kashguard/go-mpc-infra/internal/infra/storage"
	pb "github.com/kashguard/go-mpc-infra/mpc/v1"
	"github.com/rs/zerolog/log"
)

// verifyAdminPasskey 验证 Admin 的 Passkey
// selfRegistrationKey: 如果不为空，则使用该 Key 验证（用于自注册场景），否则从 DB 查找
func (s *GRPCServer) verifyAdminPasskey(ctx context.Context, adminAuth *pb.AdminAuthToken, expectedChallenge string, selfRegistrationKey string) error {
	if adminAuth == nil {
		return fmt.Errorf("missing admin auth token")
	}

	var publicKey string
	if selfRegistrationKey != "" {
		// 自注册场景：使用请求中携带的公钥验证
		publicKey = selfRegistrationKey
	} else {
		// 常规鉴权：从数据库查找 Admin 的 Passkey
		if s.metadataStore == nil {
			return fmt.Errorf("metadata store not initialized")
		}
		passkey, err := s.metadataStore.GetUserPasskey(ctx, adminAuth.UserId, adminAuth.CredentialId)
		if err != nil {
			return fmt.Errorf("failed to get admin passkey: %w", err)
		}
		publicKey = passkey.PublicKey
	}

	return auth.VerifyPasskeySignature(
		publicKey,
		adminAuth.PasskeySignature,
		adminAuth.AuthenticatorData,
		adminAuth.ClientDataJson,
		expectedChallenge,
	)
}

// SetSigningPolicy 设置签名策略
func (s *GRPCServer) SetSigningPolicy(ctx context.Context, req *pb.SetSigningPolicyRequest) (*pb.SetSigningPolicyResponse, error) {
	log.Info().
		Str("key_id", req.KeyId).
		Str("policy_type", req.PolicyType).
		Int32("min_signatures", req.MinSignatures).
		Msg("Received SetSigningPolicy request")

	// 构造 Challenge: SHA256(key_id|policy_type|min_signatures)
	challengeRaw := fmt.Sprintf("%s|%s|%d", req.KeyId, req.PolicyType, req.MinSignatures)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// 验证 Admin 权限
	if req.AdminAuth != nil {
		if err := s.verifyAdminPasskey(ctx, req.AdminAuth, expectedChallenge, ""); err != nil {
			log.Warn().Err(err).Msg("Admin passkey verification failed")
			return &pb.SetSigningPolicyResponse{
				Success: false,
				Message: fmt.Sprintf("Admin verification failed: %v", err),
			}, nil
		}
		log.Info().Str("admin_user_id", req.AdminAuth.UserId).Msg("Admin auth token verified")
	} else {
		log.Warn().Msg("Missing admin auth token for sensitive operation")
		// 严格模式下应返回错误: return nil, status.Error(codes.Unauthenticated, "missing admin auth")
	}

	if s.metadataStore == nil {
		return &pb.SetSigningPolicyResponse{
			Success: false,
			Message: "metadata store is not initialized",
		}, nil
	}

	policy := &storage.SigningPolicy{
		WalletID:      req.KeyId,
		PolicyType:    req.PolicyType,
		MinSignatures: int(req.MinSignatures),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.metadataStore.SaveSigningPolicy(ctx, policy); err != nil {
		log.Error().Err(err).Msg("Failed to save signing policy")
		return &pb.SetSigningPolicyResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.SetSigningPolicyResponse{
		Success: true,
		Message: "signing policy set successfully",
	}, nil
}

// GetSigningPolicy 获取签名策略
func (s *GRPCServer) GetSigningPolicy(ctx context.Context, req *pb.GetSigningPolicyRequest) (*pb.GetSigningPolicyResponse, error) {
	if s.metadataStore == nil {
		return nil, nil
	}

	policy, err := s.metadataStore.GetSigningPolicy(ctx, req.KeyId)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get signing policy")
		// If policy not found, return default policy (single signature)
		return &pb.GetSigningPolicyResponse{
			KeyId:         req.KeyId,
			PolicyType:    "single",
			MinSignatures: 1,
		}, nil
	}

	return &pb.GetSigningPolicyResponse{
		KeyId:         policy.WalletID,
		PolicyType:    policy.PolicyType,
		MinSignatures: int32(policy.MinSignatures),
	}, nil
}

// AddUserPasskey 添加用户 Passkey 公钥
func (s *GRPCServer) AddUserPasskey(ctx context.Context, req *pb.AddUserPasskeyRequest) (*pb.AddUserPasskeyResponse, error) {
	log.Info().
		Str("user_id", req.UserId).
		Str("credential_id", req.CredentialId).
		Str("device_name", req.DeviceName).
		Msg("Received AddUserPasskey request")

	// 构造 Challenge: SHA256(user_id|credential_id|public_key|device_name)
	challengeRaw := fmt.Sprintf("%s|%s|%s|%s", req.UserId, req.CredentialId, req.PublicKey, req.DeviceName)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// 验证 Admin 权限
	// 对于注册场景，AdminAuth 可能是用户自己的自签名
	if req.AdminAuth != nil {
		// 检查是否是自注册 (Admin UserID == Req UserID)
		selfRegKey := ""
		if req.AdminAuth.UserId == req.UserId {
			selfRegKey = req.PublicKey
		}

		if err := s.verifyAdminPasskey(ctx, req.AdminAuth, expectedChallenge, selfRegKey); err != nil {
			log.Warn().Err(err).Msg("Admin passkey verification failed for AddUserPasskey")
			return &pb.AddUserPasskeyResponse{
				Success: false,
				Message: fmt.Sprintf("Admin verification failed: %v", err),
			}, nil
		}
		log.Info().Str("admin_user_id", req.AdminAuth.UserId).Msg("Admin auth token verified")
	} else {
		log.Warn().Msg("Missing admin auth token for sensitive operation")
		// 严格模式下应返回错误
	}

	if s.metadataStore == nil {
		return &pb.AddUserPasskeyResponse{
			Success: false,
			Message: "metadata store is not initialized",
		}, nil
	}

	passkey := &storage.UserPasskey{
		UserID:       req.UserId,
		CredentialID: req.CredentialId,
		PublicKey:    req.PublicKey,
		DeviceName:   req.DeviceName,
		CreatedAt:    time.Now(),
	}

	if err := s.metadataStore.SaveUserPasskey(ctx, passkey); err != nil {
		log.Error().Err(err).Msg("Failed to save user passkey")
		return &pb.AddUserPasskeyResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.AddUserPasskeyResponse{
		Success: true,
		Message: "user passkey added successfully",
	}, nil
}
