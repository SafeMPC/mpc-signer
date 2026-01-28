package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SafeMPC/mpc-signer/internal/config"
	"github.com/SafeMPC/mpc-signer/internal/data/dto"
	"github.com/SafeMPC/mpc-signer/internal/data/local"
	"github.com/SafeMPC/mpc-signer/internal/i18n"
	"github.com/SafeMPC/mpc-signer/internal/mailer"
	"github.com/SafeMPC/mpc-signer/internal/metrics"
	"github.com/SafeMPC/mpc-signer/internal/push"
	"github.com/SafeMPC/mpc-signer/internal/util"
	"github.com/dropbox/godropbox/time2"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	// MPC imports
	"github.com/SafeMPC/mpc-signer/internal/infra/discovery"
	// infra_grpc "github.com/SafeMPC/mpc-signer/internal/infra/grpc" // 已删除
	"github.com/SafeMPC/mpc-signer/internal/infra/key"
	"github.com/SafeMPC/mpc-signer/internal/infra/session"
	"github.com/SafeMPC/mpc-signer/internal/infra/signing"
	mpcgrpc "github.com/SafeMPC/mpc-signer/internal/mpc/grpc"
	"github.com/SafeMPC/mpc-signer/internal/mpc/node"
	pb "github.com/SafeMPC/mpc-signer/pb/mpc/v1" // 引入 proto 定义，用于 RegisterNode

	// Import postgres driver for database/sql package
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Router struct {
	Routes     []*echo.Route
	Root       *echo.Group
	Management *echo.Group
	APIV1Auth  *echo.Group
	APIV1Push  *echo.Group
	APIV1Infra *echo.Group
	WellKnown  *echo.Group
}

// Server is a central struct keeping all the dependencies.
// It is initialized with wire, which handles making the new instances of the components
// in the right order. To add a new component, 3 steps are required:
// - declaring it in this struct
// - adding a provider function in providers.go
// - adding the provider's function name to the arguments of wire.Build() in wire.go
//
// Components labeled as `wire:"-"` will be skipped and have to be initialized after the InitNewServer* call.
// For more information about wire refer to https://pkg.go.dev/github.com/google/wire
type Server struct {
	// skip wire:
	// -> initialized with router.Init(s) function
	Echo   *echo.Echo `wire:"-"`
	Router *Router    `wire:"-"`

	Config  config.Server
	DB      *sql.DB
	Mailer  *mailer.Mailer
	Push    *push.Service
	I18n    *i18n.Service
	Clock   time2.Clock
	Auth    AuthService
	Local   *local.Service
	Metrics *metrics.Service

	// MPC services
	KeyService       *key.Service
	SigningService   *signing.Service
	NodeManager      *node.Manager
	NodeRegistry     *node.Registry
	NodeDiscovery    *node.Discovery
	SessionManager   *session.Manager
	DiscoveryService *discovery.Service // ✅ 新的统一服务发现

	// gRPC services (unified MPC gRPC)
	MPCGRPCServer *mpcgrpc.GRPCServer // MPC gRPC 服务端（统一实现）
	MPCGRPCClient *mpcgrpc.GRPCClient // MPC gRPC 客户端（用于节点间通信）
	// InfraGRPCServer *infra_grpc.InfrastructureServer // Infrastructure gRPC Server (Application Layer) // 已删除
}

// newServerWithComponents is used by wire to initialize the server components.
// Components not listed here won't be handled by wire and should be initialized separately.
// Components which shouldn't be handled must be labeled `wire:"-"` in Server struct.
func newServerWithComponents(
	cfg config.Server,
	db *sql.DB,
	mail *mailer.Mailer,
	pusher *push.Service,
	i18n *i18n.Service,
	clock time2.Clock,
	auth AuthService,
	local *local.Service,
	metrics *metrics.Service,
	keyService *key.Service,
	signingService *signing.Service,
	nodeManager *node.Manager,
	nodeRegistry *node.Registry,
	nodeDiscovery *node.Discovery,
	sessionManager *session.Manager,
	mpcGRPCServer *mpcgrpc.GRPCServer, // ✅ 统一的 MPC gRPC 服务端
	mpcGRPCClient *mpcgrpc.GRPCClient, // ✅ 统一的 MPC gRPC 客户端
	discoveryService *discovery.Service, // ✅ 新的统一服务发现
	// infraGRPCServer *infra_grpc.InfrastructureServer, // 已删除
) *Server {
	s := &Server{
		Config:  cfg,
		DB:      db,
		Mailer:  mail,
		Push:    pusher,
		I18n:    i18n,
		Clock:   clock,
		Auth:    auth,
		Local:   local,
		Metrics: metrics,

		KeyService:     keyService,
		SigningService: signingService,
		NodeManager:    nodeManager,
		NodeRegistry:   nodeRegistry,
		NodeDiscovery:  nodeDiscovery,
		SessionManager: sessionManager,

		MPCGRPCServer:    mpcGRPCServer,    // ✅ 统一的 MPC gRPC 服务端
		MPCGRPCClient:    mpcGRPCClient,    // ✅ 统一的 MPC gRPC 客户端
		DiscoveryService: discoveryService, // ✅ 新的统一服务发现
		// InfraGRPCServer:  infraGRPCServer, // 已删除
	}

	// 设置 NodeDiscovery 到 MPCGRPCClient，使其能够从 Consul 获取节点信息
	if s.MPCGRPCClient != nil && s.NodeDiscovery != nil {
		s.MPCGRPCClient.SetNodeDiscovery(s.NodeDiscovery)
	}

	return s
}

type AuthService interface {
	GetAppUserProfile(ctx context.Context, id string) (*dto.AppUserProfile, error)
	InitPasswordReset(ctx context.Context, request dto.InitPasswordResetRequest) (dto.InitPasswordResetResult, error)
	Login(ctx context.Context, request dto.LoginRequest) (dto.LoginResult, error)
	Logout(ctx context.Context, request dto.LogoutRequest) error
	Refresh(ctx context.Context, request dto.RefreshRequest) (dto.LoginResult, error)
	Register(ctx context.Context, request dto.RegisterRequest) (dto.RegisterResult, error)
	CompleteRegister(ctx context.Context, request dto.CompleteRegisterRequest) (dto.LoginResult, error)
	DeleteUserAccount(ctx context.Context, request dto.DeleteUserAccountRequest) error
	ResetPassword(ctx context.Context, request dto.ResetPasswordRequest) (dto.LoginResult, error)
	UpdatePassword(ctx context.Context, request dto.UpdatePasswordRequest) (dto.LoginResult, error)
}

func NewServer(config config.Server) *Server {
	s := &Server{
		Config: config,
	}

	return s
}

func (s *Server) Ready() bool {
	// Signer 节点不需要 REST API（Echo/Router），只检查必需的组件
	// 使用自定义检查，跳过 Echo 和 Router
	if s.Config.MPC.NodeType == "signer" {
		// Signer 节点只需要 gRPC 服务器和 MPC 服务
		if s.MPCGRPCServer == nil {
			log.Debug().Msg("MPC gRPC server is not initialized")
			return false
		}
		// 其他必需组件检查
		if s.DB == nil || s.KeyService == nil || s.SigningService == nil {
			log.Debug().Msg("Required MPC services are not initialized")
			return false
		}
		return true
	}

	// Service 节点需要完整的初始化（包括 Echo 和 Router）
	if err := util.IsStructInitialized(s); err != nil {
		log.Debug().Err(err).Msg("Server is not fully initialized")
		return false
	}

	return true
}

func (s *Server) Start() error {
	if !s.Ready() {
		return errors.New("server is not ready")
	}

	ctx := context.Background()

	// 1. 注册节点到服务发现（Consul）
	if s.DiscoveryService != nil && s.Config.MPC.NodeID != "" {
		// ✅ 确定注册地址：
		// 1. 如果配置了 MPC_REGISTER_ADDRESS，使用配置的地址（用于跨网络部署）
		// 2. 否则，在 docker-compose 网络中使用可解析的主机名：
		//    - coordinator 使用服务名 "coordinator"
		//    - signer 使用 nodeID（如果与服务名一致）
		var serviceHost string
		if s.Config.MPC.RegisterAddress != "" {
			// 使用配置的注册地址（可能包含端口，需要解析）
			if strings.Contains(s.Config.MPC.RegisterAddress, ":") {
				parts := strings.Split(s.Config.MPC.RegisterAddress, ":")
				serviceHost = parts[0]
			} else {
				serviceHost = s.Config.MPC.RegisterAddress
			}
		} else {
			// 默认逻辑：使用 nodeID 或服务名
			serviceHost = s.Config.MPC.NodeID
			if s.Config.MPC.NodeType == "coordinator" {
				serviceHost = "coordinator"
			}
		}

		log.Info().
			Str("node_id", s.Config.MPC.NodeID).
			Str("node_type", s.Config.MPC.NodeType).
			Str("service_host", serviceHost).
			Str("register_address", s.Config.MPC.RegisterAddress).
			Int("grpc_port", s.Config.MPC.GRPCPort).
			Msg("Registering node to Consul")

		// 1.1 V2 兼容：继续注册到 Consul (用于节点间发现)
		err := s.DiscoveryService.RegisterNode(ctx, s.Config.MPC.NodeID, s.Config.MPC.NodeType, serviceHost, s.Config.MPC.GRPCPort)
		if err != nil {
			// 注册失败不应阻止服务启动，记录警告日志
			log.Warn().
				Err(err).
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Failed to register node to service discovery, continuing startup")
		} else {
			log.Info().
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Node registered to service discovery (Consul)")
		}

		// 1.2 V3 新增：如果是 Signer 节点，还需要调用 Service 的 RegisterNode 接口
		if s.Config.MPC.NodeType == "signer" {
			go s.registerToManagementService(ctx, serviceHost)
		}
	}

	// 2. 启动 MPC gRPC 服务器（如果已初始化）
	// 注意：gRPC 服务器有自己的 Start 方法，它会在 goroutine 中运行并等待 context
	// 使用 context.Background() 让 gRPC 服务器一直运行直到显式停止
	if s.MPCGRPCServer != nil {
		go func() {
			grpcCtx := context.Background() // gRPC 服务器会一直运行，直到在 Shutdown 中显式停止
			if err := s.MPCGRPCServer.Start(grpcCtx); err != nil {
				log.Error().Err(err).Msg("MPC gRPC server failed")
			}
		}()
		log.Info().
			Int("port", s.Config.MPC.GRPCPort).
			Msg("MPC gRPC server started in background")
	}

	// Infrastructure gRPC 服务器已删除（团队签功能已移除）

	// 4. 启动 HTTP 服务器（仅 Service 节点需要）
	if s.Config.MPC.NodeType != "signer" && s.Echo != nil {
		if err := s.Echo.Start(s.Config.Echo.ListenAddress); err != nil {
			return fmt.Errorf("failed to start echo server: %w", err)
		}
	} else if s.Config.MPC.NodeType == "signer" {
		// Signer 节点只需要 gRPC 服务器，阻塞等待直到收到停止信号
		log.Info().Msg("Signer node started (gRPC only, no REST API)")
		// 使用 select 阻塞，等待 context 取消或信号
		<-ctx.Done()
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) []error {
	log.Warn().Msg("Shutting down server")

	var errs []error

	// 1. 注销节点从服务发现（Consul）
	if s.DiscoveryService != nil {
		log.Debug().Msg("Deregistering node from service discovery")
		if err := s.DiscoveryService.DeregisterNode(ctx, s.Config.MPC.NodeID, s.Config.MPC.NodeType); err != nil {
			log.Error().Err(err).Msg("Failed to deregister node from service discovery")
			errs = append(errs, err)
		} else {
			log.Info().
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Node deregistered from service discovery")
		}
	}

	// 2. 停止 MPC gRPC 服务器（如果已初始化）
	if s.MPCGRPCServer != nil {
		log.Debug().Msg("Stopping MPC gRPC server")
		if err := s.MPCGRPCServer.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop MPC gRPC server")
			errs = append(errs, err)
		}
	}

	// 3. 关闭 HTTP 服务器
	if s.Echo != nil {
		log.Debug().Msg("Shutting down echo server")
		if err := s.Echo.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("Failed to shutdown echo server")
			errs = append(errs, err)
		}
	}

	// 4. 关闭数据库连接
	if s.DB != nil {
		log.Debug().Msg("Closing database connection")
		if err := s.DB.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			log.Error().Err(err).Msg("Failed to close database connection")
			errs = append(errs, err)
		}
	}

	return errs
}

// registerToManagementService 向 Management Service 注册自己 (V3)
func (s *Server) registerToManagementService(ctx context.Context, serviceHost string) {
	// 发现 Service 节点
	// 优先使用环境变量配置的 Service 地址
	serviceAddr := os.Getenv("MPC_SERVICE_ADDR")
	if serviceAddr == "" {
		// 回退到服务发现或默认值
		// 在 docker-compose 中，Service 节点名为 "mpc-service"，端口 9091 (gRPC)
		serviceAddr = "mpc-service:9091"
	}

	log.Info().Str("service_addr", serviceAddr).Msg("Connecting to Management Service")

	// 建立 gRPC 连接
	// TODO: 在生产环境应启用 TLS
	conn, err := grpc.DialContext(ctx, serviceAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Error().Err(err).Str("service_addr", serviceAddr).Msg("Failed to connect to Management Service")
		return
	}
	defer conn.Close()

	client := pb.NewManagementServiceClient(conn)

	// 构造注册请求
	// 构造 endpoint: host:port
	endpoint := fmt.Sprintf("%s:%d", serviceHost, s.Config.MPC.GRPCPort)

	req := &pb.RegisterNodeRequest{
		NodeId:       s.Config.MPC.NodeID,
		Endpoint:     endpoint,
		Capabilities: []string{"gg20", "frost", "ecdsa", "eddsa"}, // 支持的能力
		PublicKey:    "",                                          // 可选：Signer 的身份公钥
	}

	// 循环注册和心跳
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// 首次注册
	resp, err := client.RegisterNode(ctx, req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to register node to Management Service")
	} else if resp.Registered {
		log.Info().Msg("Successfully registered node to Management Service")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 发送心跳或重新注册
			// 简单起见，这里直接调用 RegisterNode 刷新 TTL
			_, err := client.RegisterNode(ctx, req)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to refresh registration with Management Service")
				// 尝试重连？
			}
		}
	}
}
