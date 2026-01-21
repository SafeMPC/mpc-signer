package main

import (
	"fmt"
	"os"
	"time"

	"github.com/SafeMPC/mpc-signer/internal/auth"
)

func main() {
	secret := os.Getenv("MPC_JWT_SECRET")
	if secret == "" {
		secret = "change-me-in-production"
	}
	issuer := "mpc-infra"
	duration := 24 * time.Hour

	appID := os.Getenv("JWT_APP_ID")
	if appID == "" {
		appID = "test-app-001"
	}
	tenantID := os.Getenv("JWT_TENANT_ID")
	if tenantID == "" {
		tenantID = "test-tenant-001"
	}

	perms := []string{"keys:create", "keys:read", "keys:sign"}

	mgr := auth.NewJWTManager(secret, issuer, duration)
	token, err := mgr.Generate(appID, tenantID, perms)
	if err != nil {
		panic(err)
	}
	fmt.Print(token)
}
