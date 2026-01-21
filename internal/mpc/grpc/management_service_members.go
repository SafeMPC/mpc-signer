package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	pb "github.com/SafeMPC/mpc-signer/pb/mpc/v1"
	"github.com/rs/zerolog/log"
)

// AddWalletMember 添加钱包成员
func (s *GRPCServer) AddWalletMember(ctx context.Context, req *pb.AddWalletMemberRequest) (*pb.AddWalletMemberResponse, error) {
	log.Info().
		Str("wallet_id", req.WalletId).
		Str("credential_id", req.CredentialId).
		Str("role", req.Role).
		Msg("Received AddWalletMember request")

	// 构造 Challenge: SHA256(wallet_id|credential_id|role)
	challengeRaw := fmt.Sprintf("%s|%s|%s", req.WalletId, req.CredentialId, req.Role)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// 验证 Admin 权限 (阈值批准)
	if len(req.AdminAuths) > 0 {
		validAdmins := make(map[string]bool)

		// 1. 验证所有签名的合法性
		for _, auth := range req.AdminAuths {
			if err := s.verifyAdminPasskey(ctx, auth, expectedChallenge, ""); err != nil {
				log.Warn().Err(err).Str("admin_cred_id", auth.CredentialId).Msg("Admin passkey verification failed (partial)")
				continue
			}
			validAdmins[auth.CredentialId] = true
		}

		log.Info().Int("valid_admins", len(validAdmins)).Msg("Validated admin signatures")

		// 验证是否有管理权限 (Authorization) & 阈值检查
		if s.metadataStore != nil {
			// A. 检查钱包是否为空 (Bootstrapping 场景)
			members, err := s.metadataStore.ListWalletMembers(ctx, req.WalletId)
			if err != nil {
				log.Error().Err(err).Msg("Failed to list wallet members for authorization check")
				return &pb.AddWalletMemberResponse{
					Success: false,
					Message: "Internal authorization check failed",
				}, nil
			}

			if len(members) > 0 {
				// B. 钱包非空：检查所有有效签名者是否为 Admin，并统计票数
				approvedCount := 0
				for adminID := range validAdmins {
					isMember, role, err := s.metadataStore.IsWalletMember(ctx, req.WalletId, adminID)
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

				// C. 获取阈值要求
				requiredVotes := 1
				policy, err := s.metadataStore.GetSigningPolicy(ctx, req.WalletId)
				if err == nil && policy.PolicyType == "team" {
					requiredVotes = policy.MinSignatures
					// 如果 MinSignatures 为 1，建议提升到 2 (如果总 Admin 数够的话)，这里暂按策略执行
				}

				if approvedCount < requiredVotes {
					msg := fmt.Sprintf("Insufficient admin approvals: got %d, need %d", approvedCount, requiredVotes)
					log.Warn().Msg(msg)
					return &pb.AddWalletMemberResponse{
						Success: false,
						Message: msg,
					}, nil
				}

				log.Info().Int("approved_count", approvedCount).Int("required", requiredVotes).Msg("Admin threshold check passed")

			} else {
				// Bootstrapping: 只要有 1 个有效的（虽然还没有成员记录，但通过了 VerifyPasskeySignature）
				// 注意：verifyAdminPasskey 在非 Bootstrapping 下会查库，但这里还没有库记录...
				// 修正：VerifyAdminPasskey 依赖 metadataStore.GetPasskey。
				// 如果是第一个用户，Passkey 可能还没存？不，Passkey 必须先通过 AddPasskey 存入。
				// 所以 bootstrapping 流程是：AddPasskey -> AddWalletMember(self as admin)
				// 此时 validAdmins 应该至少有 1 个。
				if len(validAdmins) == 0 {
					return &pb.AddWalletMemberResponse{
						Success: false,
						Message: "No valid admin signatures for bootstrapping",
					}, nil
				}
				log.Info().Str("wallet_id", req.WalletId).Msg("Wallet is empty, allowing bootstrapping via AddWalletMember")
			}
		}
	} else {
		log.Warn().Msg("Missing admin auth tokens for sensitive operation")
		// 严格模式下应返回错误
		return &pb.AddWalletMemberResponse{
			Success: false,
			Message: "Missing admin auth tokens",
		}, nil
	}

	if s.metadataStore == nil {
		return &pb.AddWalletMemberResponse{
			Success: false,
			Message: "metadata store is not initialized",
		}, nil
	}

	if err := s.metadataStore.AddWalletMember(ctx, req.WalletId, req.CredentialId, req.Role); err != nil {
		log.Error().Err(err).Msg("Failed to add wallet member")
		return &pb.AddWalletMemberResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.AddWalletMemberResponse{
		Success: true,
		Message: "wallet member added successfully",
	}, nil
}

// RemoveWalletMember 移除钱包成员
func (s *GRPCServer) RemoveWalletMember(ctx context.Context, req *pb.RemoveWalletMemberRequest) (*pb.RemoveWalletMemberResponse, error) {
	log.Info().
		Str("wallet_id", req.WalletId).
		Str("credential_id", req.CredentialId).
		Msg("Received RemoveWalletMember request")

	// 构造 Challenge: SHA256(wallet_id|credential_id|remove)
	challengeRaw := fmt.Sprintf("%s|%s|remove", req.WalletId, req.CredentialId)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// 验证 Admin 权限 (阈值批准)
	if len(req.AdminAuths) > 0 {
		validAdmins := make(map[string]bool)

		// 1. 验证所有签名的合法性
		for _, auth := range req.AdminAuths {
			if err := s.verifyAdminPasskey(ctx, auth, expectedChallenge, ""); err != nil {
				log.Warn().Err(err).Str("admin_cred_id", auth.CredentialId).Msg("Admin passkey verification failed for RemoveWalletMember (partial)")
				continue
			}
			validAdmins[auth.CredentialId] = true
		}
		log.Info().Int("valid_admins", len(validAdmins)).Msg("Validated admin signatures for RemoveWalletMember")

		// 验证是否有管理权限 (Authorization) & 阈值检查
		if s.metadataStore != nil {
			// A. 统计有效 Admin 票数
			approvedCount := 0
			for adminID := range validAdmins {
				isMember, role, err := s.metadataStore.IsWalletMember(ctx, req.WalletId, adminID)
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

			// B. 获取阈值要求
			requiredVotes := 1
			policy, err := s.metadataStore.GetSigningPolicy(ctx, req.WalletId)
			if err == nil && policy.PolicyType == "team" {
				requiredVotes = policy.MinSignatures
			}

			if approvedCount < requiredVotes {
				msg := fmt.Sprintf("Insufficient admin approvals: got %d, need %d", approvedCount, requiredVotes)
				log.Warn().Msg(msg)
				return &pb.RemoveWalletMemberResponse{
					Success: false,
					Message: msg,
				}, nil
			}

			log.Info().Int("approved_count", approvedCount).Int("required", requiredVotes).Msg("Admin threshold check passed for RemoveWalletMember")
		}
	} else {
		log.Warn().Msg("Missing admin auth tokens for sensitive operation")
		return &pb.RemoveWalletMemberResponse{
			Success: false,
			Message: "Missing admin auth tokens",
		}, nil
	}

	if s.metadataStore == nil {
		return &pb.RemoveWalletMemberResponse{
			Success: false,
			Message: "metadata store is not initialized",
		}, nil
	}

	if err := s.metadataStore.RemoveWalletMember(ctx, req.WalletId, req.CredentialId); err != nil {
		log.Error().Err(err).Msg("Failed to remove wallet member")
		return &pb.RemoveWalletMemberResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.RemoveWalletMemberResponse{
		Success: true,
		Message: "wallet member removed successfully",
	}, nil
}
