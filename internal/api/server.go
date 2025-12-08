package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/dropbox/godropbox/time2"
	"github.com/kashguard/go-mpc-wallet/internal/config"
	"github.com/kashguard/go-mpc-wallet/internal/data/dto"
	"github.com/kashguard/go-mpc-wallet/internal/data/local"
	"github.com/kashguard/go-mpc-wallet/internal/i18n"
	"github.com/kashguard/go-mpc-wallet/internal/mailer"
	"github.com/kashguard/go-mpc-wallet/internal/metrics"
	"github.com/kashguard/go-mpc-wallet/internal/push"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"

	// MPC imports
	"github.com/kashguard/go-mpc-wallet/internal/discovery"
	"github.com/kashguard/go-mpc-wallet/internal/grpc"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/coordinator"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/participant"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/session"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/signing"

	// Import postgres driver for database/sql package
	_ "github.com/lib/pq"
)

type Router struct {
	Routes     []*echo.Route
	Root       *echo.Group
	Management *echo.Group
	APIV1Auth  *echo.Group
	APIV1Push  *echo.Group
	APIV1MPC   *echo.Group
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
	KeyService         *key.Service
	SigningService     *signing.Service
	CoordinatorService *coordinator.Service
	ParticipantService *participant.Service
	NodeManager        *node.Manager
	NodeRegistry       *node.Registry
	NodeDiscovery      *node.Discovery
	SessionManager     *session.Manager

	// gRPC services
	GRPCServer       *grpc.Server
	GRPCClient       *grpc.Client
	NodeGRPCService  *grpc.NodeService
	CoordGRPCService *grpc.CoordinatorService
	RegGRPCService   *grpc.RegistryService
	HeartbeatService *grpc.HeartbeatService
	HeartbeatManager *grpc.HeartbeatManager

	// Service discovery
	ServiceDiscovery discovery.ServiceDiscovery
	ServiceRegistry  *discovery.ServiceRegistry
	MPCDiscovery     *discovery.MPCDiscovery
	LoadBalancer     discovery.LoadBalancer
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
	coordinatorService *coordinator.Service,
	participantService *participant.Service,
	nodeManager *node.Manager,
	nodeRegistry *node.Registry,
	nodeDiscovery *node.Discovery,
	sessionManager *session.Manager,
	grpcServer *grpc.Server,
	grpcClient *grpc.Client,
	nodeGRPCService *grpc.NodeService,
	coordGRPCService *grpc.CoordinatorService,
	regGRPCService *grpc.RegistryService,
	heartbeatService *grpc.HeartbeatService,
	heartbeatManager *grpc.HeartbeatManager,
	serviceDiscovery discovery.ServiceDiscovery,
	serviceRegistry *discovery.ServiceRegistry,
	mpcDiscovery *discovery.MPCDiscovery,
	loadBalancer discovery.LoadBalancer,
) *Server {
	return &Server{
		Config:  cfg,
		DB:      db,
		Mailer:  mail,
		Push:    pusher,
		I18n:    i18n,
		Clock:   clock,
		Auth:    auth,
		Local:   local,
		Metrics: metrics,

		KeyService:         keyService,
		SigningService:     signingService,
		CoordinatorService: coordinatorService,
		ParticipantService: participantService,
		NodeManager:        nodeManager,
		NodeRegistry:       nodeRegistry,
		NodeDiscovery:      nodeDiscovery,
		SessionManager:     sessionManager,

		GRPCServer:       grpcServer,
		GRPCClient:       grpcClient,
		NodeGRPCService:  nodeGRPCService,
		CoordGRPCService: coordGRPCService,
		RegGRPCService:   regGRPCService,
		HeartbeatService: heartbeatService,
		HeartbeatManager: heartbeatManager,
		ServiceDiscovery: serviceDiscovery,
		ServiceRegistry:  serviceRegistry,
		MPCDiscovery:     mpcDiscovery,
		LoadBalancer:     loadBalancer,
	}
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
	if s.ServiceRegistry != nil {
		if err := s.ServiceRegistry.Register(ctx); err != nil {
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
				Msg("Node registered to service discovery")
		}
	}

	// 2. 启动 gRPC 服务器（如果已初始化）
	// 注意：gRPC 服务器有自己的 Start 方法，它会在 goroutine 中运行并等待 context
	// 使用 context.Background() 让 gRPC 服务器一直运行直到显式停止
	if s.GRPCServer != nil {
		go func() {
			grpcCtx := context.Background() // gRPC 服务器会一直运行，直到在 Shutdown 中显式停止
			if err := s.GRPCServer.Start(grpcCtx); err != nil {
				log.Error().Err(err).Msg("gRPC server failed")
			}
		}()
		log.Info().
			Int("port", s.Config.MPC.GRPCPort).
			Msg("MPC gRPC server started in background")
	}

	// 3. 启动 HTTP 服务器
	if err := s.Echo.Start(s.Config.Echo.ListenAddress); err != nil {
		return fmt.Errorf("failed to start echo server: %w", err)
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) []error {
	log.Warn().Msg("Shutting down server")

	var errs []error

	// 1. 注销节点从服务发现（Consul）
	if s.ServiceRegistry != nil && s.ServiceRegistry.IsRegistered() {
		log.Debug().Msg("Deregistering node from service discovery")
		if err := s.ServiceRegistry.Deregister(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to deregister node from service discovery")
			errs = append(errs, err)
		} else {
			log.Info().
				Str("node_id", s.Config.MPC.NodeID).
				Str("node_type", s.Config.MPC.NodeType).
				Msg("Node deregistered from service discovery")
		}
	}

	// 2. 停止 gRPC 服务器（如果已初始化）
	if s.GRPCServer != nil {
		log.Debug().Msg("Stopping gRPC server")
		if err := s.GRPCServer.Stop(); err != nil {
			log.Error().Err(err).Msg("Failed to stop gRPC server")
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
