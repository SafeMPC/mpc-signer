package keys

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

func GetKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.GET("/keys/:keyId", getKeyHandler(s))
}

func getKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		keyID := c.Param("keyId")
		if keyID == "" {
			return httperrors.NewHTTPError(http.StatusBadRequest, types.PublicHTTPErrorTypeGeneric, "key_id is required")
		}

		keyMetadata, err := s.KeyService.GetKey(ctx, keyID)
		if err != nil {
			log.Error().Err(err).Str("key_id", keyID).Msg("Failed to get key")
			return httperrors.NewHTTPError(http.StatusNotFound, types.PublicHTTPErrorTypeGeneric, "Key not found")
		}

		response := &types.GetKeyResponse{
			KeyID:       swag.String(keyMetadata.KeyID),
			PublicKey:   swag.String(keyMetadata.PublicKey),
			Algorithm:   swag.String(keyMetadata.Algorithm),
			Curve:       swag.String(keyMetadata.Curve),
			Threshold:   util.IntPtrToInt64Ptr(&keyMetadata.Threshold),
			TotalNodes:  util.IntPtrToInt64Ptr(&keyMetadata.TotalNodes),
			ChainType:   swag.String(keyMetadata.ChainType),
			Address:     keyMetadata.Address,
			Status:      swag.String(keyMetadata.Status),
			Description: keyMetadata.Description,
			Tags:        convertTagsToTypes(keyMetadata.Tags),
			CreatedAt:   strfmt.DateTime(keyMetadata.CreatedAt),
			UpdatedAt:   strfmt.DateTime(keyMetadata.UpdatedAt),
		}

		return util.ValidateAndReturn(c, http.StatusOK, response)
	}
}

func convertTagsToTypes(tags map[string]string) map[string]string {
	if tags == nil {
		return make(map[string]string)
	}
	return tags
}
