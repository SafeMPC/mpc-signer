package backup

import (
	"net/http"

	"github.com/kashguard/go-mpc-infra/internal/api"
	"github.com/kashguard/go-mpc-infra/internal/api/httperrors"
	pb "github.com/kashguard/go-mpc-infra/infra/v1"
	"github.com/kashguard/go-mpc-infra/internal/types"
	"github.com/kashguard/go-mpc-infra/internal/util"
	"github.com/labstack/echo/v4"
)

func PostRecoverMPCShareRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Infra.POST("/backup/shares/recover", postRecoverMPCShareHandler(s))
}

func postRecoverMPCShareHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		var body types.RecoverMPCShareRequest
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		if s.InfraGRPCServer == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Infrastructure server not available")
		}

		var shareDataBytes []byte
		if len(body.ShareData) > 0 {
			shareDataBytes = []byte(body.ShareData)
		}

		req := &pb.RecoverMPCShareRequest{
			KeyId:     body.KeyID,
			NodeId:    body.NodeID,
			ShareData: shareDataBytes,
		}

		resp, err := s.InfraGRPCServer.RecoverMPCShare(ctx, req)
		if err != nil {
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to recover share: "+err.Error())
		}

		restResp := &types.RecoverMPCShareResponse{
			KeyID:   resp.KeyId,
			NodeID:  resp.NodeId,
			Success: resp.Success,
			Message: resp.Message,
		}

		return util.ValidateAndReturn(c, http.StatusOK, restResp)
	}
}
