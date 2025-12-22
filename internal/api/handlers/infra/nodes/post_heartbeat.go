package nodes

import (
	"net/http"

	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-infra/internal/api"
	"github.com/kashguard/go-mpc-infra/internal/api/httperrors"
	pb "github.com/kashguard/go-mpc-infra/infra/v1"
	"github.com/kashguard/go-mpc-infra/internal/types"
	"github.com/kashguard/go-mpc-infra/internal/util"
	"github.com/labstack/echo/v4"
)

func PostHeartbeatRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Infra.POST("/nodes/heartbeat", postHeartbeatHandler(s))
}

func postHeartbeatHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		var body types.HeartbeatRequest
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		if s.InfraGRPCServer == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Infrastructure server not available")
		}

		req := &pb.HeartbeatRequest{
			NodeId: swag.StringValue(body.NodeID),
			Status: swag.StringValue(body.Status),
		}

		resp, err := s.InfraGRPCServer.Heartbeat(ctx, req)
		if err != nil {
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to send heartbeat: "+err.Error())
		}

		restResp := &types.HeartbeatResponse{
			Success: resp.Success,
		}

		return util.ValidateAndReturn(c, http.StatusOK, restResp)
	}
}
