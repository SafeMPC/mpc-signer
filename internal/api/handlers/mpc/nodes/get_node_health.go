package nodes

import (
	"net/http"
	"time"

	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func GetNodeHealthRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.GET("/nodes/:nodeId/health", getNodeHealthHandler(s))
}

func getNodeHealthHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		nodeID := c.Param("nodeId")
		if nodeID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "node_id is required")
		}

		// 获取节点信息
		node, err := s.NodeManager.GetNode(ctx, nodeID)
		if err != nil {
			log.Error().Err(err).Str("node_id", nodeID).Msg("Failed to get node")
			return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Node not found")
		}

		// 检查节点健康状态
		healthStatus := "healthy"
		if node.Status != "active" {
			healthStatus = "unhealthy"
		}

		// 检查心跳时间（如果超过心跳间隔的2倍，认为不健康）
		if node.LastHeartbeat != nil {
			heartbeatAge := time.Since(*node.LastHeartbeat)
			if heartbeatAge > 2*time.Minute { // 假设心跳间隔是1分钟
				healthStatus = "unhealthy"
			}
		} else {
			// 如果没有心跳记录，认为不健康
			healthStatus = "unhealthy"
		}

		response := map[string]interface{}{
			"node_id":        nodeID,
			"status":         healthStatus,
			"node_status":    node.Status,
			"last_heartbeat": node.LastHeartbeat,
			"checked_at":     time.Now(),
		}

		return c.JSON(http.StatusOK, response)
	}
}
