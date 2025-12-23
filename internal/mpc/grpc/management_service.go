package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/kashguard/go-mpc-infra/internal/auth"
	"github.com/kashguard/go-mpc-infra/internal/infra/storage"
	pb "github.com/kashguard/go-mpc-infra/pb/mpc/v1"
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
		passkey, err := s.metadataStore.GetPasskey(ctx, adminAuth.CredentialId)
		if err != nil {
			return fmt.Errorf("failed to get admin passkey: %w", err)
		}
		publicKey = passkey.PublicKey
	}

	// Backdoor for system testing (DISABLED)
	/*
		if publicKey == "mock-pub-key-hex" {
			log.Warn().Str("cred_id", adminAuth.CredentialId).Msg("Skipping WebAuthn verification for MOCK-PUB-KEY")
			return nil
		}
	*/

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

	// 验证 Admin 权限 (阈值批准)
	if len(req.AdminAuths) > 0 {
		validAdmins := make(map[string]bool)

		// 1. 验证所有签名的合法性
		for _, auth := range req.AdminAuths {
			if err := s.verifyAdminPasskey(ctx, auth, expectedChallenge, ""); err != nil {
				log.Warn().Err(err).Str("admin_cred_id", auth.CredentialId).Msg("Admin passkey verification failed for SetSigningPolicy (partial)")
				continue
			}
			validAdmins[auth.CredentialId] = true
		}
		log.Info().Int("valid_admins", len(validAdmins)).Msg("Validated admin signatures for SetSigningPolicy")

		// 验证是否有管理权限 (Authorization) & 阈值检查
		if s.metadataStore != nil {
			// A. 统计有效 Admin 票数
			approvedCount := 0
			for adminID := range validAdmins {
				isMember, role, err := s.metadataStore.IsWalletMember(ctx, req.KeyId, adminID)
				if err != nil {
					log.Error().Err(err).Str("admin_id", adminID).Msg("Failed to check admin membership role")
					continue
				}
				if isMember && role == "admin" {
					approvedCount++
				} else {
					log.Warn().Str("admin_id", adminID).Msg("Signer is not an admin, ignoring vote")
				}
			}

			// B. 获取当前阈值要求 (如果已有策略)
			// 如果是首次设置策略 (GetSigningPolicy 返回 err 或默认值)，可能需要特殊的 Bootstrapping 逻辑？
			// 但 SetSigningPolicy 通常是在钱包创建后由 Admin 设置的。
			// 如果钱包已有成员，则必须满足现有策略的 MinSignatures。
			requiredVotes := 1
			currentPolicy, err := s.metadataStore.GetSigningPolicy(ctx, req.KeyId)
			if err == nil && currentPolicy.PolicyType == "team" {
				requiredVotes = currentPolicy.MinSignatures
			} else {
				// 尝试检查钱包是否为空（Bootstrapping）
				// 但 SetSigningPolicy 不像 AddWalletMember 那样是“加人”，而是“定规矩”。
				// 如果还没有策略，默认需要 1 个 Admin 批准即可。
				// 如果钱包还没有成员，SetSigningPolicy 可能没有意义（谁来批准？）。
				// 通常流程是：StartDKG (Bootstrap Admin) -> AddWalletMember (Add Admins) -> SetSigningPolicy (Raise Threshold)
				// 所以这里 requiredVotes = 1 是合理的起点。
			}

			if approvedCount < requiredVotes {
				msg := fmt.Sprintf("Insufficient admin approvals: got %d, need %d", approvedCount, requiredVotes)
				log.Warn().Msg(msg)
				return &pb.SetSigningPolicyResponse{
					Success: false,
					Message: msg,
				}, nil
			}

			log.Info().Int("approved_count", approvedCount).Int("required", requiredVotes).Msg("Admin threshold check passed for SetSigningPolicy")
		}
	} else {
		log.Warn().Msg("Missing admin auth tokens for sensitive operation")
		return &pb.SetSigningPolicyResponse{
			Success: false,
			Message: "Missing admin auth tokens",
		}, nil
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

// AddPasskey 添加用户 Passkey 公钥
func (s *GRPCServer) AddPasskey(ctx context.Context, req *pb.AddPasskeyRequest) (*pb.AddPasskeyResponse, error) {
	log.Info().
		Str("credential_id", req.CredentialId).
		Str("device_name", req.DeviceName).
		Msg("Received AddPasskey request")

	// 构造 Challenge: SHA256(credential_id|public_key|device_name)
	challengeRaw := fmt.Sprintf("%s|%s|%s", req.CredentialId, req.PublicKey, req.DeviceName)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// 验证 Admin 权限
	// 对于注册场景，AdminAuth 可能是用户自己的自签名
	if req.AdminAuth != nil {
		// 检查是否是自注册 (Admin CredentialID == Req CredentialID)
		selfRegKey := ""
		if req.AdminAuth.CredentialId == req.CredentialId {
			selfRegKey = req.PublicKey
		}

		if err := s.verifyAdminPasskey(ctx, req.AdminAuth, expectedChallenge, selfRegKey); err != nil {
			log.Warn().Err(err).Msg("Admin passkey verification failed for AddPasskey")
			return &pb.AddPasskeyResponse{
				Success: false,
				Message: fmt.Sprintf("Admin verification failed: %v", err),
			}, nil
		}
		log.Info().Str("admin_cred_id", req.AdminAuth.CredentialId).Msg("Admin auth token verified")
	} else {
		log.Warn().Msg("Missing admin auth token for sensitive operation")
		// 严格模式下应返回错误
	}

	if s.metadataStore == nil {
		return &pb.AddPasskeyResponse{
			Success: false,
			Message: "metadata store is not initialized",
		}, nil
	}

	passkey := &storage.Passkey{
		CredentialID: req.CredentialId,
		PublicKey:    req.PublicKey,
		DeviceName:   req.DeviceName,
		CreatedAt:    time.Now(),
	}

	if err := s.metadataStore.SavePasskey(ctx, passkey); err != nil {
		log.Error().Err(err).Msg("Failed to save user passkey")
		return &pb.AddPasskeyResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.AddPasskeyResponse{
		Success: true,
		Message: "passkey added successfully",
	}, nil
}
