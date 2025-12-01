package nodes

import (
	"net/http"
	"strconv"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/storage"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func GetListNodesRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.GET("/nodes", getListNodesHandler(s))
}

func getListNodesHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		nodeType := c.QueryParam("node_type")
		status := c.QueryParam("status")
		limit := 50
		offset := 0

		if limitStr := c.QueryParam("limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil {
				limit = l
			}
		}

		if offsetStr := c.QueryParam("offset"); offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil {
				offset = o
			}
		}

		filter := &storage.NodeFilter{
			NodeType: nodeType,
			Status:   status,
			Limit:    limit,
			Offset:   offset,
		}

		nodes, err := s.NodeManager.ListNodes(ctx, filter)
		if err != nil {
			log.Error().Err(err).Msg("Failed to list nodes")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to list nodes")
		}

		responseNodes := make([]*types.GetNodeResponse, len(nodes))
		for i, n := range nodes {
			responseNodes[i] = &types.GetNodeResponse{
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
				responseNodes[i].LastHeartbeat = strfmt.DateTime(*n.LastHeartbeat)
			}
		}

		response := &types.ListNodesResponse{
			Nodes:  responseNodes,
			Total:  int64(len(nodes)),
			Limit:  int64(limit),
			Offset: int64(offset),
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
