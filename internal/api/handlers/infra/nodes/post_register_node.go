package nodes

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-infra/internal/api"
	"github.com/kashguard/go-mpc-infra/internal/api/httperrors"
	pb "github.com/kashguard/go-mpc-infra/infra/v1"
	"github.com/kashguard/go-mpc-infra/internal/types"
	"github.com/kashguard/go-mpc-infra/internal/util"
	"github.com/labstack/echo/v4"
)

func PostRegisterNodeRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Infra.POST("/nodes/register", postRegisterNodeHandler(s))
}

func postRegisterNodeHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		var body types.NodeRegistration
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		if s.InfraGRPCServer == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Infrastructure server not available")
		}

		req := &pb.RegisterNodeRequest{
			DeviceId:  swag.StringValue(body.DeviceID),
			PublicKey: swag.StringValue(body.PublicKey),
			Type:      "client",
			Version:   body.Version,
			Metadata:  body.Metadata,
		}

		resp, err := s.InfraGRPCServer.RegisterNode(ctx, req)
		if err != nil {
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to register node: "+err.Error())
		}

		restResp := &types.NodeRegistrationResponse{
			NodeID:       resp.NodeId,
			Status:       resp.Status,
			RegisteredAt: strfmt.DateTime(resp.RegisteredAt.AsTime()),
		}

		return util.ValidateAndReturn(c, http.StatusCreated, restResp)
	}
}
