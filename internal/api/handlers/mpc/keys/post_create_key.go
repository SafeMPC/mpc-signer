package keys

import (
	"net/http"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/kashguard/go-mpc-wallet/internal/api"
	"github.com/kashguard/go-mpc-wallet/internal/api/httperrors"
	"github.com/kashguard/go-mpc-wallet/internal/mpc/key"
	"github.com/kashguard/go-mpc-wallet/internal/types"
	"github.com/kashguard/go-mpc-wallet/internal/util"
	"github.com/labstack/echo/v4"
)

func PostCreateKeyRoute(s *api.Server) *echo.Route {
	return s.Router.APIV1MPC.POST("/keys", postCreateKeyHandler(s))
}

func postCreateKeyHandler(s *api.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		log := util.LogFromContext(ctx)

		var body types.PostCreateKeyPayload
		if err := util.BindAndValidateBody(c, &body); err != nil {
			return err
		}

		req := &key.CreateKeyRequest{
			Algorithm:   swag.StringValue(body.Algorithm),
			Curve:       swag.StringValue(body.Curve),
			Threshold:   int(swag.Int64Value(body.Threshold)),
			TotalNodes:  int(swag.Int64Value(body.TotalNodes)),
			ChainType:   swag.StringValue(body.ChainType),
			Description: body.Description,
			Tags:        convertTags(body.Tags),
		}

		keyMetadata, err := s.KeyService.CreateKey(ctx, req)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create key")
			return httperrors.NewHTTPError(http.StatusInternalServerError, types.PublicHTTPErrorTypeGeneric, "Failed to create key")
		}

		response := &types.CreateKeyResponse{
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
			Tags:        body.Tags,
			CreatedAt:   strfmt.DateTime(keyMetadata.CreatedAt),
		}

		return util.ValidateAndReturn(c, http.StatusCreated, response)
	}
}

func convertTags(tags map[string]string) map[string]string {
	if tags == nil {
		return make(map[string]string)
	}
	return tags
}
