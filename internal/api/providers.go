package api

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-mpc-wallet/internal/auth"
	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/discovery"
	"github.com/kashguard/go-mpc-wallet/internal/grpc"
	"github.com/kashguard/go-mpc-wallet/internal/i18n"
	"github.com/kashguard/go-mpc-wallet/internal/mailer"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/communication"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/coordinator"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/participant"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/protocol"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/signing"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/kashguard/go-mpc-wallet/internal/persistence"
	"github.com/kashguard/go-mpc-wallet/internal/push"
	"github.com/kashguard/go-mpc-wallet/internal/push/provider"
	"github.com/kashguard/tss-lib/tss"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// PROVIDERS - define here only providers that for various reasons (e.g. cyclic dependency) can't live in their corresponding packages
// or for wrapping providers that only accept sub-configs to prevent the requirements for defining providers for sub-configs.
// https://github.com/google/wire/blob/main/docs/guide.md#defining-providers

// NewPush creates an instance of the push service and registers the configured push providers.
func NewPush(cfg config.Server, db *sql.DB) (*push.Service, error) {
	pusher := push.New(db)

	if cfg.Push.UseFCMProvider {
		fcmProvider, err := provider.NewFCM(cfg.FCMConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create FCM provider: %w", err)
		}
		pusher.RegisterProvider(fcmProvider)
	}

	if cfg.Push.UseMockProvider {
		log.Warn().Msg("Initializing mock push provider")
		mockProvider := provider.NewMock(push.ProviderTypeFCM)
		pusher.RegisterProvider(mockProvider)
	}

	if pusher.GetProviderCount() < 1 {
		log.Warn().Msg("No providers registered for push service")
	}

	return pusher, nil
}

func NewClock(t ...*testing.T) time2.Clock {
	var clock time2.Clock

	useMock := len(t) > 0 && t[0] != nil

	if useMock {
		clock = time2.NewMockClock(time.Now())
	} else {
		clock = time2.DefaultClock
	}

	return clock
}

func NewAuthService(config config.Server, db *sql.DB, clock time2.Clock) *auth.Service {
	return auth.NewService(config, db, clock)
}

func NewMailer(config config.Server) (*mailer.Mailer, error) {
	return mailer.NewWithConfig(config.Mailer, config.SMTP)
}

func NewDB(config config.Server) (*sql.DB, error) {
	return persistence.NewDB(config.Database)
}

func NewI18N(config config.Server) (*i18n.Service, error) {
	return i18n.New(config.I18n)
}

func NoTest() []*testing.T {
	return nil
}

func NewMetadataStore(db *sql.DB) storage.MetadataStore {
	return storage.NewPostgreSQLStore(db)
}

func NewRedisClient(cfg config.Server) (*redis.Client, error) {
	if cfg.MPC.RedisEndpoint == "" {
		return nil, fmt.Errorf("MPC RedisEndpoint is not configured")
	}

	client := redis.NewClient(&redis.Options{
		Addr: cfg.MPC.RedisEndpoint,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return client, nil
}

func NewSessionStore(client *redis.Client) storage.SessionStore {
	return storage.NewRedisStore(client)
}

func NewKeyShareStorage(cfg config.Server) (storage.KeyShareStorage, error) {
	if cfg.MPC.KeyShareStoragePath == "" {
		return nil, fmt.Errorf("MPC KeyShareStoragePath is not configured")
	}
	if cfg.MPC.KeyShareEncryptionKey == "" {
		return nil, fmt.Errorf("MPC KeyShareEncryptionKey is not configured")
	}
	return storage.NewFileSystemKeyShareStorage(cfg.MPC.KeyShareStoragePath, cfg.MPC.KeyShareEncryptionKey)
}

func NewMPCGRPCClient(cfg config.Server, nodeManager *node.Manager) (*communication.GRPCClient, error) {
	return communication.NewGRPCClient(cfg, nodeManager)
}

func NewMPCGRPCServer(
	cfg config.Server,
	protocolEngine protocol.Engine,
	sessionManager *session.Manager,
) (*communication.GRPCServer, error) {
	nodeID := cfg.MPC.NodeID
	if nodeID == "" {
		nodeID = "default-node"
	}
	return communication.NewGRPCServer(cfg, protocolEngine, sessionManager, nodeID), nil
}

func NewProtocolEngine(cfg config.Server, grpcClient *communication.GRPCClient) protocol.Engine {
	curve := "secp256k1"
	thisNodeID := cfg.MPC.NodeID
	if thisNodeID == "" {
		thisNodeID = "default-node"
	}

	// 使用真正的gRPC客户端作为消息路由器
	// 参数：sessionID（用于DKG或签名会话），nodeID（目标节点），msg（tss-lib消息）
	messageRouter := func(sessionID string, nodeID string, msg tss.Message) error {
		ctx := context.Background()
		// 根据会话ID判断消息类型（DKG或签名）
		// 如果sessionID是keyID格式（以"key-"开头），则作为DKG消息处理
		// 否则作为签名消息处理
		if len(sessionID) > 0 && sessionID[:4] == "key-" {
			// DKG消息
			return grpcClient.SendKeygenMessage(ctx, nodeID, msg, sessionID)
		} else {
			// 签名消息
			return grpcClient.SendSigningMessage(ctx, nodeID, msg, sessionID)
		}
	}

	if len(cfg.MPC.SupportedProtocols) > 0 {
		// future: switch based on protocol type
	}

	return protocol.NewGG20Protocol(curve, thisNodeID, messageRouter)
}

func NewNodeManager(metadataStore storage.MetadataStore, cfg config.Server) *node.Manager {
	heartbeat := time.Duration(cfg.MPC.SessionTimeout)
	if heartbeat <= 0 {
		heartbeat = 30
	}
	return node.NewManager(metadataStore, heartbeat*time.Second)
}

func NewNodeRegistry(manager *node.Manager) *node.Registry {
	return node.NewRegistry(manager)
}

func NewNodeDiscovery(manager *node.Manager) *node.Discovery {
	return node.NewDiscovery(manager)
}

func NewSessionManager(metadataStore storage.MetadataStore, sessionStore storage.SessionStore, cfg config.Server) *session.Manager {
	timeout := time.Duration(cfg.MPC.SessionTimeout)
	if timeout <= 0 {
		timeout = 300
	}
	return session.NewManager(metadataStore, sessionStore, timeout*time.Second)
}

func NewDKGServiceProvider(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
) *key.DKGService {
	return key.NewDKGService(metadataStore, keyShareStorage, protocolEngine, nodeManager, nodeDiscovery)
}

func NewKeyServiceProvider(
	metadataStore storage.MetadataStore,
	keyShareStorage storage.KeyShareStorage,
	protocolEngine protocol.Engine,
	dkgService *key.DKGService,
) *key.Service {
	return key.NewService(metadataStore, keyShareStorage, protocolEngine, dkgService)
}

func NewSigningServiceProvider(keyService *key.Service, protocolEngine protocol.Engine, sessionManager *session.Manager, nodeDiscovery *node.Discovery) *signing.Service {
	return signing.NewService(keyService, protocolEngine, sessionManager, nodeDiscovery)
}

func NewCoordinatorServiceProvider(
	metadataStore storage.MetadataStore,
	keyService *key.Service,
	signingService *signing.Service,
	sessionManager *session.Manager,
	nodeManager *node.Manager,
	nodeDiscovery *node.Discovery,
	protocolEngine protocol.Engine,
) *coordinator.Service {
	return coordinator.NewService(metadataStore, keyService, signingService, sessionManager, nodeManager, nodeDiscovery, protocolEngine)
}

func NewParticipantServiceProvider(cfg config.Server, keyShareStorage storage.KeyShareStorage, protocolEngine protocol.Engine) *participant.Service {
	return participant.NewService(cfg.MPC.NodeID, keyShareStorage, protocolEngine)
}

// gRPC相关Provider

// NewGRPCServer 创建gRPC服务器
func NewGRPCServer(cfg config.Server) (*grpc.Server, error) {
	return grpc.NewServer(&cfg)
}

// NewGRPCClient 创建gRPC客户端
func NewGRPCClient(cfg config.Server) (*grpc.Client, error) {
	return grpc.NewClient(&grpc.Config{
		Target:  fmt.Sprintf("localhost:%d", cfg.MPC.GRPCPort),
		TLS:     cfg.MPC.TLSEnabled,
		Timeout: 30 * time.Second,
	})
}

// NewNodeService 创建节点gRPC服务
func NewNodeService(cfg config.Server) *grpc.NodeService {
	return grpc.NewNodeService(cfg.MPC.NodeID)
}

// NewCoordinatorService 创建协调器gRPC服务
func NewCoordinatorService(cfg config.Server) *grpc.CoordinatorService {
	return grpc.NewCoordinatorService(cfg.MPC.NodeID)
}

// NewRegistryService 创建注册gRPC服务
func NewRegistryService() *grpc.RegistryService {
	return grpc.NewRegistryService()
}

// NewHeartbeatService 创建心跳服务
func NewHeartbeatService(cfg config.Server, client *grpc.Client) *grpc.HeartbeatService {
	return grpc.NewHeartbeatService(&grpc.HeartbeatConfig{
		NodeID:        cfg.MPC.NodeID,
		CoordinatorID: "coordinator", // TODO: 动态获取
		Interval:      30 * time.Second,
		Timeout:       10 * time.Second,
		Client:        client,
	})
}

// NewHeartbeatManager 创建心跳管理器
func NewHeartbeatManager() *grpc.HeartbeatManager {
	return grpc.NewHeartbeatManager()
}

// 服务发现相关Provider

// NewConsulDiscovery 创建Consul服务发现
func NewConsulDiscovery(cfg config.Server) (discovery.ServiceDiscovery, error) {
	return discovery.NewConsulDiscovery(cfg.MPC.ConsulAddress)
}

// NewServiceRegistry 创建服务注册管理器
func NewServiceRegistry(discoverySvc discovery.ServiceDiscovery, cfg config.Server) *discovery.ServiceRegistry {
	// 确保 NodeID 不为空，如果为空则生成默认值
	nodeID := cfg.MPC.NodeID
	if nodeID == "" {
		// 生成基于节点类型和时间戳的默认ID
		nodeID = fmt.Sprintf("%s-%d", cfg.MPC.NodeType, time.Now().Unix())
	}

	// 从配置获取服务地址
	serviceHost := discovery.GetServiceHost(cfg)

	// 构建服务ID
	serviceID := fmt.Sprintf("mpc-%s-%s", cfg.MPC.NodeType, nodeID)

	serviceInfo := &discovery.ServiceInfo{
		ID:      serviceID,
		Name:    fmt.Sprintf("mpc-%s", cfg.MPC.NodeType),
		Address: serviceHost,
		Port:    cfg.MPC.GRPCPort,
		Tags: []string{
			fmt.Sprintf("node-type:%s", cfg.MPC.NodeType),
			fmt.Sprintf("node-id:%s", nodeID),
			"protocol:v1",
		},
		Meta: map[string]string{
			"node_id":   nodeID,
			"node_type": cfg.MPC.NodeType,
			"version":   "v1.0.0",
			"weight":    "1",
		},
		NodeType: cfg.MPC.NodeType,
		Protocol: "v1",
		Weight:   1,
		Check: &discovery.HealthCheck{
			Type:                           "grpc",
			Interval:                       30 * time.Second,
			Timeout:                        5 * time.Second,
			DeregisterCriticalServiceAfter: 5 * time.Minute,
		},
	}

	loadBalancer := discovery.NewRoundRobinLoadBalancer()
	return discovery.NewServiceRegistry(discoverySvc, serviceInfo, loadBalancer)
}

// NewMPCDiscovery 创建MPC服务发现
func NewMPCDiscovery(registry *discovery.ServiceRegistry, nodeManager *node.Manager, nodeDiscovery *node.Discovery) *discovery.MPCDiscovery {
	return discovery.NewMPCDiscovery(registry, nodeManager, nodeDiscovery)
}

// NewLoadBalancer 创建负载均衡器
func NewLoadBalancer() discovery.LoadBalancer {
	return discovery.NewRoundRobinLoadBalancer()
}
