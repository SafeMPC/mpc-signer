package httperrors

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/labstack/echo/v4"
)

// HTTPError HTTP错误结构
type HTTPError struct {
	Code           *int64                 `json:"code"`
	Type           *string                `json:"type"`
	Title          *string                `json:"title"`
	Detail         string                 `json:"detail,omitempty"`
	Internal       error                  `json:"-"`
	AdditionalData map[string]interface{} `json:"-"`
}

func NewHTTPError(code int, errorType string, title string) *HTTPError {
	return &HTTPError{
		Code:  swag.Int64(int64(code)),
		Type:  swag.String(errorType),
		Title: swag.String(title),
	}
}

func NewHTTPErrorWithDetail(code int, errorType string, title string, detail string) *HTTPError {
	return &HTTPError{
		Code:   swag.Int64(int64(code)),
		Type:   swag.String(errorType),
		Title:  swag.String(title),
		Detail: detail,
	}
}

func NewFromEcho(e *echo.HTTPError) *HTTPError {
	return NewHTTPError(e.Code, "generic", http.StatusText(e.Code))
}

// Validate implements the Validatable interface for go-openapi
func (e *HTTPError) Validate(formats strfmt.Registry) error {
	// HTTPError is a simple error type, no validation needed
	return nil
}

func (e *HTTPError) Error() string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "HTTPError %d (%s): %s", *e.Code, *e.Type, *e.Title)

	if len(e.Detail) > 0 {
		fmt.Fprintf(&builder, " - %s", e.Detail)
	}
	if e.Internal != nil {
		fmt.Fprintf(&builder, ", %v", e.Internal)
	}
	if len(e.AdditionalData) > 0 {
		keys := make([]string, 0, len(e.AdditionalData))
		for k := range e.AdditionalData {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		builder.WriteString(". Additional: ")
		for i, k := range keys {
			fmt.Fprintf(&builder, "%s=%v", k, e.AdditionalData[k])
			if i < len(keys)-1 {
				builder.WriteString(", ")
			}
		}
	}

	return builder.String()
}

// HTTPValidationError HTTP验证错误结构
type HTTPValidationError struct {
	HTTPError
	ValidationErrors []interface{} `json:"validationErrors"` // 使用 interface{} 以兼容不同的类型
}

func NewHTTPValidationError(code int, errorType interface{}, title string, validationErrors []interface{}) *HTTPValidationError {
	var errorTypeStr string
	if str, ok := errorType.(string); ok {
		errorTypeStr = str
	} else if str, ok := errorType.(fmt.Stringer); ok {
		errorTypeStr = str.String()
	} else {
		errorTypeStr = fmt.Sprintf("%v", errorType)
	}

	return &HTTPValidationError{
		HTTPError: HTTPError{
			Code:  swag.Int64(int64(code)),
			Type:  swag.String(errorTypeStr),
			Title: swag.String(title),
		},
		ValidationErrors: validationErrors,
	}
}

func NewHTTPValidationErrorWithDetail(code int, errorType interface{}, title string, validationErrors []interface{}, detail string) *HTTPValidationError {
	var errorTypeStr string
	if str, ok := errorType.(string); ok {
		errorTypeStr = str
	} else if str, ok := errorType.(fmt.Stringer); ok {
		errorTypeStr = str.String()
	} else {
		errorTypeStr = fmt.Sprintf("%v", errorType)
	}

	return &HTTPValidationError{
		HTTPError: HTTPError{
			Code:   swag.Int64(int64(code)),
			Type:   swag.String(errorTypeStr),
			Title:  swag.String(title),
			Detail: detail,
		},
		ValidationErrors: validationErrors,
	}
}

func (e *HTTPValidationError) Error() string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "HTTPValidationError %d (%s): %s", *e.Code, *e.Type, *e.Title)

	if len(e.Detail) > 0 {
		fmt.Fprintf(&builder, " - %s", e.Detail)
	}
	if e.Internal != nil {
		fmt.Fprintf(&builder, ", %v", e.Internal)
	}

	builder.WriteString(" - Validation: ")
	for i, ve := range e.ValidationErrors {
		fmt.Fprintf(&builder, "%v", ve)
		if i < len(e.ValidationErrors)-1 {
			builder.WriteString(", ")
		}
	}

	return builder.String()
}
