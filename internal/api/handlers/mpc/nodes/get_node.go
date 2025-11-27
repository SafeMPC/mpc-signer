package nodes

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func GetNodeRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.GET("/nodes/:nodeId", getNodeHandler(s))
}

func getNodeHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		nodeID := c.Param("nodeId")
		if nodeID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "node_id is required")
		}

		n, err := s.NodeManager.GetNode(ctx, nodeID)
		if err != nil {
			log.Error().Err(err).Str("node_id", nodeID).Msg("Failed to get node")
			return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Node not found")
		}

		response := &types.GetNodeResponse{
			NodeID:       swag.String(n.NodeID),
			NodeType:     swag.String(n.NodeType),
			Status:       swag.String(n.Status),
			Endpoint:     swag.String(n.Endpoint),
			PublicKey:    n.PublicKey,
			Capabilities: n.Capabilities,
			Metadata:     convertMetadata(n.Metadata),
			RegisteredAt: strfmt.DateTime(n.RegisteredAt),
		}
		if n.LastHeartbeat != nil {
			response.LastHeartbeat = strfmt.DateTime(*n.LastHeartbeat)
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}

func convertMetadata(metadata map[string]interface{}) map[string]string {
	result := make(map[string]string)
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			result[k] = str
		}
	}
	return result
}
