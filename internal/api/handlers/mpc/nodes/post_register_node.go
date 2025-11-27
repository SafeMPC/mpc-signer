package nodes

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/node"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostRegisterNodeRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/nodes", postRegisterNodeHandler(s))
}

func postRegisterNodeHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostRegisterNodePayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		var registeredNode *node.Node
		var err error

		if body.NodeType == nil {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "node_type is required")
		}

		switch string(*body.NodeType) {
		case "coordinator":
			registeredNode, err = s.NodeRegistry.RegisterCoordinator(ctx, string(*body.Endpoint), string(*body.PublicKey))
		case "participant":
			capabilities := convertCapabilities(body.Capabilities)
			registeredNode, err = s.NodeRegistry.RegisterParticipant(ctx, string(*body.Endpoint), string(*body.PublicKey), capabilities)
		default:
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "invalid node_type")
		}

		if err != nil {
			log.Error().Err(err).Msg("Failed to register node")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to register node")
		}

		response := buildNodeResponse(registeredNode)
		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}

func convertCapabilities(caps []string) []string {
	if caps == nil {
		return []string{}
	}
	return caps
}

func buildNodeResponse(n *node.Node) *types.RegisterNodeResponse {
	resp := &types.RegisterNodeResponse{
		NodeID:       swag.String(n.NodeID),
		NodeType:     swag.String(n.NodeType),
		Status:       swag.String(n.Status),
		Endpoint:     swag.String(n.Endpoint),
		PublicKey:    n.PublicKey,
		Capabilities: n.Capabilities,
		RegisteredAt: strfmt.DateTime(n.RegisteredAt),
	}
	if n.LastHeartbeat != nil {
		resp.LastHeartbeat = strfmt.DateTime(*n.LastHeartbeat)
	}
	return resp
}
