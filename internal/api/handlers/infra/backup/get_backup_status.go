package backup

import (
	"net/http"

	"github.com/kashguard/go-mpc-infra/internal/api"
	"github.com/kashguard/go-mpc-infra/internal/api/httperrors"
	pb "github.com/kashguard/go-mpc-infra/infra/v1"
	"github.com/kashguard/go-mpc-infra/internal/types"
	backupTypes "github.com/kashguard/go-mpc-infra/internal/types/backup"
	"github.com/kashguard/go-mpc-infra/internal/util"
	"github.com/labstack/echo/v4"
)

func GetBackupStatusRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Infra.GET("/backup/status", getBackupStatusHandler(s))
}

func getBackupStatusHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		var params backupTypes.GetBackupStatusParams
		if err := util.BindAndValidateQueryParams(c, &params); err != nil {
			return err
		}

		if s.InfraGRPCServer == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Infrastructure server not available")
		}

		req := &pb.GetBackupStatusRequest{
			KeyId: params.KeyID,
		}

		resp, err := s.InfraGRPCServer.GetBackupStatus(ctx, req)
		if err != nil {
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to get status: "+err.Error())
		}

		statuses := make([]*types.BackupStatus, len(resp.Statuses))
		for i, st := range resp.Statuses {
			statuses[i] = &types.BackupStatus{
				NodeID:         st.NodeId,
				TotalShares:    int64(st.TotalShares),
				RequiredShares: int64(st.RequiredShares),
				Recoverable:    st.Recoverable,
			}
		}

		restResp := &types.GetBackupStatusResponse{
			KeyID:    resp.KeyId,
			Statuses: statuses,
		}

		return util.ValidateAndReturn(c, http.StatusOK, restResp)
	}
}
