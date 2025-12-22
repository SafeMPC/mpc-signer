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

func GetListBackupSharesRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1Infra.GET("/backup/shares", getListBackupSharesHandler(s))
}

func getListBackupSharesHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()

		var params backupTypes.ListBackupSharesParams
		if err := util.BindAndValidateQueryParams(c, &params); err != nil {
			return err
		}

		if s.InfraGRPCServer == nil {
			return httperrors.NewHTTPError(http.StatusServiceUnavailable, types.PublicHTTPErrorTypeGeneric, "Infrastructure server not available")
		}

		req := &pb.ListBackupSharesRequest{
			KeyId: params.KeyID,
		}
		if params.NodeID != nil {
			req.NodeId = *params.NodeID
		}

		resp, err := s.InfraGRPCServer.ListBackupShares(ctx, req)
		if err != nil {
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to list shares: "+err.Error())
		}

		sharesByNode := make(map[string]types.BackupShares)
		for k, v := range resp.SharesByNode {
			shares := make([]*types.BackupShare, len(v.Shares))
			for i, sh := range v.Shares {
				shares[i] = &types.BackupShare{
					KeyID:      sh.KeyId,
					NodeID:     sh.NodeId,
					ShareIndex: int64(sh.ShareIndex),
					CreatedAt:  sh.CreatedAt,
				}
			}
			sharesByNode[k] = types.BackupShares{
				NodeID: v.NodeId,
				Shares: shares,
			}
		}

		restResp := &types.ListBackupSharesResponse{
			KeyID:        resp.KeyId,
			SharesByNode: sharesByNode,
		}

		return util.ValidateAndReturn(c, http.StatusOK, restResp)
	}
}
