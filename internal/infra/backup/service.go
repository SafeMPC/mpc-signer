package backup

import (
	"context"

	"github.com/SafeMPC/mpc-signer/internal/infra/storage"
	"github.com/pkg/errors"
)

// SSSBackupService SSS 备份服务接口
type SSSBackupService interface {
	// GenerateBackupShares 对单个MPC分片生成SSS备份分片
	// 注意：输入是单个MPC分片，不是完整密钥
	GenerateBackupShares(ctx context.Context, mpcShare []byte, threshold, totalShares int) ([]*BackupShare, error)

	// RecoverMPCShareFromBackup 从备份分片恢复单个MPC分片
	// 注意：恢复的是MPC分片，不是完整密钥
	RecoverMPCShareFromBackup(ctx context.Context, shares []*BackupShare) ([]byte, error)
}

// Service SSS 备份服务实现
type Service struct {
	sss           *SSS
	backupStorage storage.BackupShareStorage
	metadataStore storage.MetadataStore
}

// NewService 创建 SSS 备份服务
func NewService(
	backupStorage storage.BackupShareStorage,
	metadataStore storage.MetadataStore,
) SSSBackupService {
	return &Service{
		sss:           NewSSS(),
		backupStorage: backupStorage,
		metadataStore: metadataStore,
	}
}

// GenerateBackupShares 对单个MPC分片生成SSS备份分片
func (s *Service) GenerateBackupShares(
	ctx context.Context,
	mpcShare []byte,
	threshold int,
	totalShares int,
) ([]*BackupShare, error) {
	if len(mpcShare) == 0 {
		return nil, errors.New("MPC share cannot be empty")
	}
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if totalShares < threshold {
		return nil, errors.New("total shares must be at least threshold")
	}

	// 使用SSS算法对单个MPC分片进行分割
	shareDataList, err := s.sss.Split(mpcShare, totalShares, threshold)
	if err != nil {
		return nil, errors.Wrap(err, "failed to split MPC share using SSS")
	}

	// 转换为BackupShare结构
	backupShares := make([]*BackupShare, len(shareDataList))
	for i, shareData := range shareDataList {
		backupShares[i] = &BackupShare{
			ShareIndex: i + 1,
			ShareData:  shareData,
		}
	}

	return backupShares, nil
}

// RecoverMPCShareFromBackup 从备份分片恢复单个MPC分片
func (s *Service) RecoverMPCShareFromBackup(
	ctx context.Context,
	shares []*BackupShare,
) ([]byte, error) {
	if len(shares) < 3 {
		return nil, errors.New("insufficient backup shares: need at least 3")
	}

	// 提取备份分片数据
	shareData := make([][]byte, len(shares))
	for i, share := range shares {
		shareData[i] = share.ShareData
	}

	// 使用SSS算法恢复MPC分片（不是完整密钥）
	mpcShare, err := s.sss.Combine(shareData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to recover MPC share from backup")
	}

	return mpcShare, nil
}
