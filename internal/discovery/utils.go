package discovery

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/kashguard/go-mpc-wallet/internal/config"
)

// ParseEndpoint 解析 endpoint 格式（如 "host:port" 或 "host"）
// 如果 endpoint 包含端口，返回解析的地址和端口
// 如果 endpoint 不包含端口，返回地址和默认端口
func ParseEndpoint(endpoint string, defaultPort int) (host string, port int, err error) {
	if endpoint == "" {
		return "localhost", defaultPort, nil
	}

	// 尝试解析为 "host:port" 格式
	host, portStr, err := net.SplitHostPort(endpoint)
	if err == nil {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port in endpoint %s: %w", endpoint, err)
		}
		return host, port, nil
	}

	// 如果不是 "host:port" 格式，尝试解析为 URL
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		u, err := url.Parse(endpoint)
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse endpoint as URL: %w", err)
		}
		host = u.Hostname()
		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil {
				return "", 0, fmt.Errorf("invalid port in URL: %w", err)
			}
		} else {
			port = defaultPort
		}
		return host, port, nil
	}

	// 否则，整个字符串作为 host，使用默认端口
	return endpoint, defaultPort, nil
}

// BuildServiceAddress 构建服务地址
func BuildServiceAddress(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// GetServiceHost 从配置获取服务主机地址
// 优先级：
// 1. 从 SERVER_ECHO_BASE_URL 解析（如果包含主机名）
// 2. 默认值 "localhost"
// 注意：在 Docker 容器中，应该使用容器服务名或配置的环境变量
func GetServiceHost(cfg config.Server) string {
	// 从 BaseURL 解析主机名
	if cfg.Echo.BaseURL != "" {
		u, err := url.Parse(cfg.Echo.BaseURL)
		if err == nil && u.Hostname() != "" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			return u.Hostname()
		}
	}

	// 默认返回 localhost（在 Docker 中，Consul 会使用容器网络，所以 localhost 是可以的）
	return "localhost"
}
