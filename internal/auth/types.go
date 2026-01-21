package auth

import (
	"time"

	"github.com/SafeMPC/mpc-signer/internal/data/dto"
)

type Result struct {
	Token      string
	User       *dto.User
	ValidUntil time.Time
	Scopes     []string
}
