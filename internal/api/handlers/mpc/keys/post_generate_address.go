package keys

import (
	"net/http"

	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostGenerateAddressRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/keys/:keyId/address", postGenerateAddressHandler(s))
}

func postGenerateAddressHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "key_id is required")
		}

		chainType := c.QueryParam("chain_type")
		if chainType == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "chain_type is required")
		}

		address, err := s.KeyService.GenerateAddress(ctx, keyID, chainType)
		if err != nil {
			log.Error().Err(err).Str("key_id", keyID).Str("chain_type", chainType).Msg("Failed to generate address")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to generate address")
		}

		response := &types.GenerateAddressResponse{
			KeyID:     &keyID,
			ChainType: &chainType,
			Address:   &address,
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}
