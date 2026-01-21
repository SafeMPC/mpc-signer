package main

import (
	"fmt"
	"time"

	"github.com/SafeMPC/mpc-signer/internal/auth"
)

func main() {
	// Default secret from config/server_config.go
	secret := "change-me-in-production"
	mgr := auth.NewJWTManager(secret, "mpc-infra", time.Hour*24)

	// Generate token with appID="curl-test"
	token, err := mgr.Generate("curl-test", "default-tenant", []string{"app"})
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
}
