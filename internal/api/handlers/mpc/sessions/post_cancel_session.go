package sessions

import (
	"net/http"

	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostCancelSessionRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/sessions/:sessionId/cancel", postCancelSessionHandler(s))
}

func postCancelSessionHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		sessionID := c.Param("sessionId")
		if sessionID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "session_id is required")
		}

		err := s.SessionManager.CancelSession(ctx, sessionID)
		if err != nil {
			log.Error().Err(err).Str("session_id", sessionID).Msg("Failed to cancel session")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to cancel session")
		}

		response := map[string]interface{}{
			"session_id": sessionID,
			"status":     "cancelled",
		}

		return c.JSON(http.StatusOK, response)
	}
}
