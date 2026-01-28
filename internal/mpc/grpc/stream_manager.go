package grpc

import (
	"context"
	"fmt"
	"sync"

	pb "github.com/SafeMPC/mpc-signer/pb/mpc/v1"
	"github.com/rs/zerolog/log"
)

// StreamManager 管理与 Client 的 gRPC 直连流
type StreamManager struct {
	mu      sync.RWMutex
	streams map[string]pb.SignerService_ParticipateServer
	waiters map[string][]chan struct{}
}

// NewStreamManager 创建流管理器
func NewStreamManager() *StreamManager {
	return &StreamManager{
		streams: make(map[string]pb.SignerService_ParticipateServer),
		waiters: make(map[string][]chan struct{}),
	}
}

// Register 注册流
func (m *StreamManager) Register(nodeID string, stream pb.SignerService_ParticipateServer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams[nodeID] = stream
	for _, ch := range m.waiters[nodeID] {
		close(ch)
	}
	delete(m.waiters, nodeID)
	log.Debug().Str("node_id", nodeID).Msg("Registered participate stream")
}

// Unregister 注销流
func (m *StreamManager) Unregister(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, nodeID)
	for _, ch := range m.waiters[nodeID] {
		close(ch)
	}
	delete(m.waiters, nodeID)
	log.Debug().Str("node_id", nodeID).Msg("Unregistered participate stream")
}

// Get 获取流
func (m *StreamManager) Get(nodeID string) (pb.SignerService_ParticipateServer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stream, ok := m.streams[nodeID]
	return stream, ok
}

func (m *StreamManager) WaitForStream(ctx context.Context, nodeID string) (pb.SignerService_ParticipateServer, error) {
	if stream, ok := m.Get(nodeID); ok {
		return stream, nil
	}

	ch := make(chan struct{})
	m.mu.Lock()
	if stream, ok := m.streams[nodeID]; ok {
		m.mu.Unlock()
		return stream, nil
	}
	m.waiters[nodeID] = append(m.waiters[nodeID], ch)
	m.mu.Unlock()

	select {
	case <-ch:
		if stream, ok := m.Get(nodeID); ok {
			return stream, nil
		}
		return nil, fmt.Errorf("stream not found for node %s", nodeID)
	case <-ctx.Done():
		m.mu.Lock()
		waiters := m.waiters[nodeID]
		for i := range waiters {
			if waiters[i] == ch {
				m.waiters[nodeID] = append(waiters[:i], waiters[i+1:]...)
				break
			}
		}
		if len(m.waiters[nodeID]) == 0 {
			delete(m.waiters, nodeID)
		}
		m.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Send 发送消息到指定节点的流
func (m *StreamManager) Send(nodeID string, resp *pb.ParticipateResponse) error {
	stream, ok := m.Get(nodeID)
	if !ok {
		return fmt.Errorf("stream not found for node %s", nodeID)
	}
	return stream.Send(resp)
}

func (m *StreamManager) SendWithWait(ctx context.Context, nodeID string, resp *pb.ParticipateResponse) error {
	stream, err := m.WaitForStream(ctx, nodeID)
	if err != nil {
		return err
	}
	return stream.Send(resp)
}
