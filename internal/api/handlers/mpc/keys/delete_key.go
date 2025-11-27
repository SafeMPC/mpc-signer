package keys

import (
	"net/http"

	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func DeleteKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.DELETE("/keys/:keyId", deleteKeyHandler(s))
}

func deleteKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "key_id is required")
		}

		if err := s.KeyService.DeleteKey(ctx, keyID); err != nil {
			log.Error().Err(err).Str("key_id", keyID).Msg("Failed to delete key")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to delete key")
		}

		return c.NoContent(http.StatusOK)
	}
}
