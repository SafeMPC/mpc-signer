package sessions

import (
	"net/http"

	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostJoinSessionRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/sessions/:sessionId/join", postJoinSessionHandler(s))
}

func postJoinSessionHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		sessionID := c.Param("sessionId")
		if sessionID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "session_id is required")
		}

		nodeID := c.QueryParam("node_id")
		if nodeID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "node_id is required")
		}

		err := s.SessionManager.JoinSession(ctx, sessionID, nodeID)
		if err != nil {
			log.Error().Err(err).Str("session_id", sessionID).Str("node_id", nodeID).Msg("Failed to join session")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to join session")
		}

		response := map[string]interface{}{
			"session_id": sessionID,
			"node_id":    nodeID,
			"status":     "joined",
		}

		return c.JSON(http.StatusOK, response)
	}
}
