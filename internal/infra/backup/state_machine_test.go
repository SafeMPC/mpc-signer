package backup

import (
	"context"
	"testing"
	"time"

	"github.com/SafeMPC/mpc-signer/internal/infra/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStore is a mock implementation of Store
type MockStore struct {
	mock.Mock
}

func (m *MockStore) SaveBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int, shareData []byte) error {
	args := m.Called(ctx, keyID, nodeID, shareIndex, shareData)
	return args.Error(0)
}

func (m *MockStore) GetBackupShare(ctx context.Context, keyID, nodeID string, shareIndex int) ([]byte, error) {
	args := m.Called(ctx, keyID, nodeID, shareIndex)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockStore) ListBackupShares(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareInfo, error) {
	args := m.Called(ctx, keyID, nodeID)
	return args.Get(0).([]*storage.BackupShareInfo), args.Error(1)
}

func (m *MockStore) SaveBackupShareDelivery(ctx context.Context, delivery *storage.BackupShareDelivery) error {
	args := m.Called(ctx, delivery)
	return args.Error(0)
}

func (m *MockStore) GetBackupShareDelivery(ctx context.Context, keyID, nodeID string, shareIndex int) (*storage.BackupShareDelivery, error) {
	args := m.Called(ctx, keyID, nodeID, shareIndex)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.BackupShareDelivery), args.Error(1)
}

func (m *MockStore) UpdateBackupShareDeliveryStatus(ctx context.Context, keyID, nodeID string, shareIndex int, status string, reason string) error {
	args := m.Called(ctx, keyID, nodeID, shareIndex, status, reason)
	return args.Error(0)
}

func (m *MockStore) ListBackupShareDeliveries(ctx context.Context, keyID, nodeID string) ([]*storage.BackupShareDelivery, error) {
	args := m.Called(ctx, keyID, nodeID)
	return args.Get(0).([]*storage.BackupShareDelivery), args.Error(1)
}

func TestStateMachine_StartDelivery(t *testing.T) {
	mockStore := new(MockStore)
	sm := NewStateMachine(mockStore)
	ctx := context.Background()

	keyID := "key1"
	nodeID := "node1"
	index := 1

	// Case 1: New delivery
	mockStore.On("GetBackupShareDelivery", ctx, keyID, nodeID, index).Return(nil, nil).Once()
	mockStore.On("SaveBackupShareDelivery", ctx, mock.AnythingOfType("*storage.BackupShareDelivery")).Return(nil).Once()

	delivery, err := sm.StartDelivery(ctx, keyID, nodeID, index)
	assert.NoError(t, err)
	assert.Equal(t, DeliveryStatusPending, delivery.Status)
	mockStore.AssertExpectations(t)

	// Case 2: Existing pending delivery
	existing := &storage.BackupShareDelivery{
		KeyID:     keyID,
		Status:    DeliveryStatusPending,
		CreatedAt: time.Now(),
	}
	mockStore.On("GetBackupShareDelivery", ctx, keyID, nodeID, index).Return(existing, nil)

	delivery2, err := sm.StartDelivery(ctx, keyID, nodeID, index)
	assert.NoError(t, err)
	assert.Equal(t, existing, delivery2)
}

func TestStateMachine_Transitions(t *testing.T) {
	mockStore := new(MockStore)
	sm := NewStateMachine(mockStore)
	ctx := context.Background()

	keyID := "key1"
	nodeID := "node1"
	index := 1

	// Setup initial state
	delivery := &storage.BackupShareDelivery{
		KeyID:      keyID,
		NodeID:     nodeID,
		ShareIndex: index,
		Status:     DeliveryStatusPending,
	}

	// Pending -> Delivered
	mockStore.On("GetBackupShareDelivery", ctx, keyID, nodeID, index).Return(delivery, nil).Once()
	mockStore.On("UpdateBackupShareDeliveryStatus", ctx, keyID, nodeID, index, DeliveryStatusDelivered, "").Return(nil).Once()

	err := sm.TransitionToDelivered(ctx, keyID, nodeID, index)
	assert.NoError(t, err)
	delivery.Status = DeliveryStatusDelivered // Simulate update

	// Delivered -> Confirmed
	mockStore.On("GetBackupShareDelivery", ctx, keyID, nodeID, index).Return(delivery, nil).Once()
	mockStore.On("UpdateBackupShareDeliveryStatus", ctx, keyID, nodeID, index, DeliveryStatusConfirmed, "").Return(nil).Once()

	err = sm.TransitionToConfirmed(ctx, keyID, nodeID, index)
	assert.NoError(t, err)
	delivery.Status = DeliveryStatusConfirmed // Simulate update

	// Confirmed -> Failed (Should fail)
	mockStore.On("GetBackupShareDelivery", ctx, keyID, nodeID, index).Return(delivery, nil).Once()

	err = sm.TransitionToFailed(ctx, keyID, nodeID, index, "error")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state transition")
}
