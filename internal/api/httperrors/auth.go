package httperrors

import (
	"net/http"
)

var (
	ErrForbiddenUserDeactivated  = NewHTTPError(http.StatusForbidden, "USER_DEACTIVATED", "User account is deactivated")
	ErrBadRequestInvalidPassword = NewHTTPErrorWithDetail(http.StatusBadRequest, "INVALID_PASSWORD", "The password provided was invalid", "Password was either too weak or did not match other criteria")
	ErrForbiddenNotLocalUser     = NewHTTPError(http.StatusForbidden, "NOT_LOCAL_USER", "User account is not valid for local authentication")
	ErrNotFoundTokenNotFound     = NewHTTPError(http.StatusNotFound, "TOKEN_NOT_FOUND", "Provided token was not found")
	ErrConflictTokenExpired      = NewHTTPError(http.StatusConflict, "TOKEN_EXPIRED", "Provided token has expired and is no longer valid")
	ErrConflictUserAlreadyExists = NewHTTPError(http.StatusConflict, "USER_ALREADY_EXISTS", "User with given username already exists")
	ErrBadRequestZeroFileSize    = NewHTTPError(http.StatusBadRequest, "ZERO_FILE_SIZE", "File size of 0 is not supported.")
	ErrConflictPushToken         = NewHTTPError(http.StatusConflict, "PUSH_TOKEN_ALREADY_EXISTS", "The given token already exists.")
	ErrNotFoundOldPushToken      = NewHTTPError(http.StatusNotFound, "OLD_PUSH_TOKEN_NOT_FOUND", "The old push token does not exists. The new token was saved.")
)
