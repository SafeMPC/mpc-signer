package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/SafeMPC/mpc-signer/internal/types/infrastructure"
)

const (
	baseURL   = "http://localhost:8080"
	jwtSecret = "change-me-in-production" // Default from server_config.go
)

func main() {
	log.Println("Starting System Test...")

	// Initialize Global Authenticator (Simulate WebAuthn Device)
	var err error
	globalAuthenticator, err = NewAuthenticator()
	if err != nil {
		log.Fatalf("Failed to initialize authenticator: %v", err)
	}
	log.Printf("Initialized Virtual Authenticator: CredentialID=%s", globalAuthenticator.CredentialID)

	// 0. Wait for server (optional, manual check preferred in this script)
	if err := checkHealth(); err != nil {
		log.Fatalf("Health check failed: %v. Please ensure server is running (make run-server or docker-compose up).", err)
	}

	// 1. Register Node
	// Note: Register node also requires E2EJWT
	nodeID := fmt.Sprintf("test-node-%d", time.Now().Unix())
	if err := registerNode(nodeID); err != nil {
		log.Printf("Warning: Register node failed (might already exist or be invalid in this env): %v. Continuing...", err)
	} else {
		log.Println("Node registered successfully")
	}

	// 2. Create Key (Wallet)
	keyID, err := createKey()
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	log.Printf("Created Key ID: %s", keyID)

	// 3. Add Admin Passkey (Bootstrap)
	adminCredID := globalAuthenticator.CredentialID
	if err := addPasskey(adminCredID); err != nil {
		log.Printf("Failed to add admin passkey: %v", err)
	} else {
		log.Println("Admin Passkey added successfully")
	}

	// 3.1 Bootstrap Wallet Admin
	// Add the first admin (self-signed)
	if err := addMember(keyID, adminCredID); err != nil {
		log.Fatalf("Failed to bootstrap wallet admin: %v", err)
	}
	log.Println("Wallet admin bootstrapped successfully")

	// 4. Set Signing Policy
	if err := setPolicy(keyID); err != nil {
		log.Fatalf("Failed to set policy: %v", err)
	}
	log.Println("Policy set successfully")

	// 5. Get Signing Policy
	if err := getPolicy(keyID); err != nil {
		log.Fatalf("Failed to get policy: %v", err)
	}
	log.Println("Policy verified successfully")

	// 6. Add Member
	newCredID := fmt.Sprintf("member-cred-%d", time.Now().Unix())
	if err := addMember(keyID, newCredID); err != nil {
		log.Fatalf("Failed to add member: %v", err)
	}
	log.Println("Member added successfully")

	// 7. Remove Member
	if err := removeMember(keyID, newCredID); err != nil {
		log.Fatalf("Failed to remove member: %v", err)
	}
	log.Println("Member removed successfully")

	// 8. Sign Transaction (Threshold Signing)
	// Using admin cred to authorize signing
	if err := signTransaction(keyID, adminCredID); err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}
	log.Println("Transaction signed successfully")

	log.Println("System Test Completed Successfully!")
}

func signTransaction(keyID, credID string) error {
	// Sign Payload
	// Message to sign (e.g. hash of transaction)
	msg := "Hello World Transaction"
	reqID := "req-sign-1"

	// Sign using global authenticator (assuming credID matches)
	if credID != globalAuthenticator.CredentialID {
		return fmt.Errorf("signTransaction only supports global authenticator in this test")
	}

	// For transaction signing, the challenge is the base64url encoded message
	challenge := base64.RawURLEncoding.EncodeToString([]byte(msg))
	signature, authData, clientData, err := globalAuthenticator.Sign(challenge, "http://localhost:8080")
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	pubKeyHex, err := globalAuthenticator.PublicKeyCOSEHex()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// We need 1 auth token because policy min_signatures=1
	authTokens := []map[string]interface{}{
		{
			"req_id":             reqID,
			"credential_id":      credID,
			"passkey_signature":  base64.StdEncoding.EncodeToString(signature),
			"authenticator_data": base64.StdEncoding.EncodeToString(authData),
			"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
			"public_key":         pubKeyHex,
			"signature":          base64.StdEncoding.EncodeToString(signature), // Duplicating for different validation requirements
		},
	}

	payload := map[string]interface{}{
		"key_id":       keyID,
		"message":      base64.StdEncoding.EncodeToString([]byte(msg)),
		"message_type": "raw", // or "hash" if we send hex
		"chain_type":   "ethereum",
		"auth_tokens":  authTokens,
	}

	var resp struct {
		Signature string `json:"signature"`
		SessionID string `json:"session_id"`
	}

	// The endpoint is likely /api/v1/infra/sign based on handler
	if err := postRequest("/api/v1/infra/sign", payload, &resp); err != nil {
		return err
	}

	if resp.Signature == "" {
		return fmt.Errorf("empty signature received")
	}

	log.Printf("Received Signature: %s (Session: %s)", resp.Signature, resp.SessionID)
	return nil
}

// --- Real WebAuthn Authenticator Implementation ---

var globalAuthenticator *Authenticator

type Authenticator struct {
	PrivateKey   *ecdsa.PrivateKey
	CredentialID string
}

func NewAuthenticator() (*Authenticator, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}
	return &Authenticator{
		PrivateKey:   privateKey,
		CredentialID: base64.RawURLEncoding.EncodeToString(credID),
	}, nil
}

func (a *Authenticator) PublicKeyCOSEHex() (string, error) {
	// Construct COSE Key for P-256
	// kty: 2 (EC2)
	// alg: -7 (ES256)
	// crv: 1 (P-256)
	// x, y: coordinates
	publicKey := a.PrivateKey.PublicKey
	coseKey := map[int]interface{}{
		1:  2,
		3:  -7,
		-1: 1,
		-2: publicKey.X.Bytes(),
		-3: publicKey.Y.Bytes(),
	}

	data, err := cbor.Marshal(coseKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func (a *Authenticator) Sign(challenge string, origin string) (signature, authData, clientData []byte, err error) {
	// 1. Construct ClientDataJSON
	clientDataMap := map[string]string{
		"type":      "webauthn.get",
		"challenge": challenge,
		"origin":    origin,
	}
	clientData, err = json.Marshal(clientDataMap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal client data: %w", err)
	}

	// 2. Construct AuthenticatorData
	// RP ID Hash (32 bytes)
	// For "localhost", we just hash it. The server might not strictly check RP ID in this simplified setup,
	// or it expects the RP ID configured in server.
	// Let's assume "localhost" or the domain from config.
	rpIDHash := sha256.Sum256([]byte("localhost"))

	// Flags (1 byte)
	// Bit 0: UP (User Present) = 1
	// Bit 2: UV (User Verified) = 0 (or 1 if we want to simulate verification)
	// Bit 6: AT (Attested Credential Data) = 0 (since this is assertion, not registration)
	// Bit 7: ED (Extension Data) = 0
	flags := byte(0x01) // UP

	// Counter (4 bytes)
	counter := []byte{0, 0, 0, 0}

	authData = append(rpIDHash[:], flags)
	authData = append(authData, counter...)

	// 3. Sign: authData || sha256(clientDataJSON)
	clientDataHash := sha256.Sum256(clientData)
	signedData := append(authData, clientDataHash[:]...)

	hash := sha256.Sum256(signedData)
	r, s, err := ecdsa.Sign(rand.Reader, a.PrivateKey, hash[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Convert to ASN.1 DER
	ecdsaSig := struct {
		R, S *big.Int
	}{R: r, S: s}

	signature, err = asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return signature, authData, clientData, nil
}

func generateAdminAuth(reqID string) (map[string]interface{}, error) {
	// For Admin Auth, the challenge is typically the ReqID.
	// But check server side:
	// management_service_members.go: challengeRaw := fmt.Sprintf("%s|%s|%s", req.WalletId, req.CredentialId, req.Role)
	// management_service.go (verifyAdminPasskey): accepts expectedChallenge
	// management_service.go (SetSigningPolicy): challengeRaw := fmt.Sprintf("%s|%s|%d", req.KeyId, req.PolicyType, req.MinSignatures)

	// WAIT: verifyAdminPasskey is called with different challenges depending on the operation.
	// The `reqID` parameter here is confusing if it's not the actual challenge string.
	// In AddWalletMember:
	// challengeRaw := fmt.Sprintf("%s|%s|%s", req.WalletId, req.CredentialId, req.Role)
	// expectedChallenge := base64.RawURLEncoding.EncodeToString(sha256(challengeRaw))

	// So this helper function `generateAdminAuth` cannot just sign `reqID`.
	// It needs to sign the actual challenge expected by the server for that specific operation.
	// We should pass the `challenge` string to this function instead of `reqID`.

	// However, `reqID` is also a field in AdminAuthToken struct.
	// Let's rename parameter to `challenge` and also take `reqID`.

	return nil, fmt.Errorf("generateAdminAuth requires specific challenge")
}

func generateAdminAuthForChallenge(reqID string, challenge string) (map[string]interface{}, error) {
	signature, authData, clientData, err := globalAuthenticator.Sign(challenge, "http://localhost:8080")
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"req_id":             reqID,
		"credential_id":      globalAuthenticator.CredentialID,
		"passkey_signature":  base64.StdEncoding.EncodeToString(signature),
		"authenticator_data": base64.StdEncoding.EncodeToString(authData),
		"client_data_json":   base64.StdEncoding.EncodeToString(clientData),
	}, nil
}

func checkHealth() error {
	// The health check endpoint is protected by a management secret
	resp, err := http.Get(baseURL + "/-/healthy?mgmt-secret=mgmtpass")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	return nil
}

func registerNode(nodeID string) error {
	// Simple registration payload
	// The server expects types.NodeRegistration which has DeviceID, PublicKey, etc.
	// Map fields: "device_id", "public_key", "version", "metadata"
	payload := map[string]interface{}{
		"device_id":  nodeID,
		"public_key": "mock-pub-key",
		"version":    "1.0.0",
		"metadata": map[string]string{
			"address": "http://localhost:8080",
		},
	}
	return postRequest("/api/v1/infra/nodes/register", payload, nil)
}

func createKey() (string, error) {
	// Create Key Payload
	payload := map[string]interface{}{
		"curve":       "secp256k1",
		"algorithm":   "ECDSA", // Must be uppercase
		"threshold":   2,
		"total_nodes": 3,
		"chain_type":  "ethereum", // Required field
	}
	var resp struct {
		KeyID string `json:"key_id"`
	}
	if err := postRequest("/api/v1/infra/keys", payload, &resp); err != nil {
		return "", err
	}
	return resp.KeyID, nil
}

func addPasskey(credID string) error {
	// Real WebAuthn Public Key
	pubKeyHex, err := globalAuthenticator.PublicKeyCOSEHex()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	payload := map[string]interface{}{
		"credential_id": credID,
		"public_key":    pubKeyHex,
		"attestation":   "none",
		"device_name":   "Test Device (Real Crypto)",
	}
	return postRequest("/api/v1/infra/passkeys", payload, nil)
}

func setPolicy(keyID string) error {
	// Set Policy Payload
	reqID := "req-1"

	// Calculate Challenge for SetSigningPolicy
	// Server: challengeRaw := fmt.Sprintf("%s|%s|%d", req.KeyId, req.PolicyType, req.MinSignatures)
	challengeRaw := fmt.Sprintf("%s|%s|%d", keyID, "team", 1)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return fmt.Errorf("failed to generate admin auth: %w", err)
	}

	adminAuths := []map[string]interface{}{authEntry}

	// Using map to avoid import cycle or complex struct setup if types not available
	mapPayload := map[string]interface{}{
		"policy_type":    "team",
		"min_signatures": 1,
		"admin_auths":    adminAuths,
	}

	return putRequest(fmt.Sprintf("/api/v1/infra/wallets/%s/policy", keyID), mapPayload, nil)
}

func getPolicy(keyID string) error {
	var resp infrastructure.SigningPolicyResponse
	if err := getRequest(fmt.Sprintf("/api/v1/infra/wallets/%s/policy", keyID), &resp); err != nil {
		return err
	}
	if resp.MinSignatures != 1 {
		return fmt.Errorf("expected min_signatures 1, got %d", resp.MinSignatures)
	}
	return nil
}

func addMember(keyID, credID string) error {
	// Add Member Payload
	reqID := "req-1"

	// Calculate Challenge for AddWalletMember
	// Server: challengeRaw := fmt.Sprintf("%s|%s|%s", req.WalletId, req.CredentialId, req.Role)
	challengeRaw := fmt.Sprintf("%s|%s|%s", keyID, credID, "admin")
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return fmt.Errorf("failed to generate admin auth: %w", err)
	}
	adminAuths := []map[string]interface{}{authEntry}

	payload := map[string]interface{}{
		"credential_id": credID,
		"role":          "admin",
		"name":          "New Member",
		"admin_auths":   adminAuths,
	}
	return postRequest(fmt.Sprintf("/api/v1/infra/wallets/%s/members", keyID), payload, nil)
}

func removeMember(keyID, credID string) error {
	// Remove Member Payload
	reqID := "req-1"

	// Calculate Challenge for RemoveWalletMember
	// Server: challengeRaw := fmt.Sprintf("%s|%s|remove", req.WalletId, req.CredentialId)
	challengeRaw := fmt.Sprintf("%s|%s|remove", keyID, credID)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return fmt.Errorf("failed to generate admin auth: %w", err)
	}
	adminAuths := []map[string]interface{}{authEntry}

	// DELETE request usually doesn't have body in standard HTTP, but our API might expect it.
	// However, standard DELETE with body is discouraged.
	// Let's check how deleteMemberHandler handles it.
	// Assuming it's a DELETE request with body for admin auths.
	// If standard http client doesn't support body in DELETE, we need to construct it carefully.
	// But let's try standard way first, many clients support it.

	payload := map[string]interface{}{
		"credential_id": credID,
		"admin_auths":   adminAuths,
	}

	// We need a deleteRequest helper
	return deleteRequest(fmt.Sprintf("/api/v1/infra/wallets/%s/members", keyID), payload, nil)
}

func generateToken() (string, error) {
	claims := jwt.MapClaims{
		"app_id":      "system-test",
		"tenant_id":   "system-test-tenant",
		"permissions": []string{"admin"},
		"exp":         time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func postRequest(path string, payload interface{}, result interface{}) error {
	return sendRequest("POST", path, payload, result)
}

func putRequest(path string, payload interface{}, result interface{}) error {
	return sendRequest("PUT", path, payload, result)
}

func getRequest(path string, result interface{}) error {
	return sendRequest("GET", path, nil, result)
}

// Helper for DELETE with body
func deleteRequest(path string, payload interface{}, result interface{}) error {
	return sendRequest("DELETE", path, payload, result)
}

func sendRequest(method, path string, payload interface{}, result interface{}) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewBuffer(data)
	}

	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Add Auth Token
	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 120 * time.Second} // Increased timeout for DKG
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error: %d - %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decode error: %v (body: %s)", err, string(respBody))
		}
	}

	return nil
}
