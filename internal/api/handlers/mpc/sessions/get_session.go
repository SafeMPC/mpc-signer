package sessions

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func GetSessionRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.GET("/sessions/:sessionId", getSessionHandler(s))
}

func getSessionHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		sessionID := c.Param("sessionId")
		if sessionID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "session_id is required")
		}

		session, err := s.SessionManager.GetSession(ctx, sessionID)
		if err != nil {
			log.Error().Err(err).Str("session_id", sessionID).Msg("Failed to get session")
			return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Session not found")
		}

		threshold := int64(session.Threshold)
		totalNodes := int64(session.TotalNodes)
		currentRound := int64(session.CurrentRound)
		totalRounds := int64(session.TotalRounds)
		durationMs := int64(session.DurationMs)

		response := &types.GetSessionResponse{
			SessionID:          swag.String(session.SessionID),
			KeyID:              swag.String(session.KeyID),
			Protocol:           swag.String(session.Protocol),
			Status:             swag.String(session.Status),
			Threshold:          threshold,
			TotalNodes:         totalNodes,
			ParticipatingNodes: session.ParticipatingNodes,
			CurrentRound:       currentRound,
			TotalRounds:        totalRounds,
			Signature:          session.Signature,
			CreatedAt:          strfmt.DateTime(session.CreatedAt),
			DurationMs:         durationMs,
		}

		if session.CompletedAt != nil {
			response.CompletedAt = strfmt.DateTime(*session.CompletedAt)
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
