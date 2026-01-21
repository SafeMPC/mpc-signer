package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	infrav1 "github.com/SafeMPC/mpc-signer/pb/infra/v1"
	mpcv1 "github.com/SafeMPC/mpc-signer/pb/mpc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultInfraAddr = "localhost:9094"
	defaultMPCAddr   = "localhost:9090"
)

const (
	baseURL = "http://localhost:8080"
)

var globalAuthenticator *Authenticator
var teamAuthenticator2 *Authenticator
var teamAuthenticator3 *Authenticator

func main() {
	infraAddr := flag.String("infra-addr", defaultInfraAddr, "Infra gRPC address")
	mpcAddr := flag.String("mpc-addr", defaultMPCAddr, "MPC gRPC address")
	certDir := flag.String("cert-dir", "./certs", "Directory containing certificates")
	insecureConn := flag.Bool("insecure", false, "Use insecure gRPC connection (no TLS)")
	flag.Parse()

	log.Println("Starting gRPC System Test...")

	// Initialize Authenticator
	var err error
	globalAuthenticator, err = NewAuthenticator()
	if err != nil {
		log.Fatalf("Failed to initialize authenticator: %v", err)
	}
	log.Printf("Initialized Virtual Authenticator: CredentialID=%s", globalAuthenticator.CredentialID)

	// Initialize two more authenticators to simulate 3-person team
	teamAuthenticator2, err = NewAuthenticator()
	if err != nil {
		log.Fatalf("Failed to initialize team authenticator 2: %v", err)
	}
	teamAuthenticator3, err = NewAuthenticator()
	if err != nil {
		log.Fatalf("Failed to initialize team authenticator 3: %v", err)
	}
	log.Printf("Team Authenticators: A2=%s, A3=%s", teamAuthenticator2.CredentialID, teamAuthenticator3.CredentialID)

	var dialOpt grpc.DialOption
	if *insecureConn {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		creds, err := loadTLSCredentials(*certDir)
		if err != nil {
			log.Fatalf("Failed to load TLS credentials: %v", err)
		}
		dialOpt = grpc.WithTransportCredentials(creds)
	}

	// Connect to Infra
	infraConn, err := grpc.Dial(*infraAddr, dialOpt)
	if err != nil {
		log.Fatalf("Failed to connect to Infra: %v", err)
	}
	defer infraConn.Close()
	keyClient := infrav1.NewKeyServiceClient(infraConn)
	nodeClient := infrav1.NewNodeServiceClient(infraConn)
	signingClient := infrav1.NewSigningServiceClient(infraConn)

	// Connect to MPC
	mpcConn, err := grpc.Dial(*mpcAddr, dialOpt)
	if err != nil {
		log.Fatalf("Failed to connect to MPC: %v", err)
	}
	defer mpcConn.Close()
	mpcMgmtClient := mpcv1.NewMPCManagementClient(mpcConn)

	ctx := context.Background()

	// 1. Register Node
	nodeID := fmt.Sprintf("test-node-grpc-%d", time.Now().Unix())
	if err := registerNode(ctx, nodeClient, nodeID); err != nil {
		log.Printf("Warning: Register node failed: %v", err)
	} else {
		log.Println("Node registered successfully")
	}

	// 2. Create Key
	keyID, err := createKey(ctx, keyClient)
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	log.Printf("Created Key ID: %s", keyID)

	// 3. Add Admin Passkey
	adminCredID := globalAuthenticator.CredentialID
	if err := addPasskey(ctx, mpcMgmtClient, adminCredID); err != nil {
		log.Fatalf("Failed to add admin passkey: %v", err)
	}
	log.Println("Admin Passkey added successfully")

	// 3.1 Bootstrap Wallet Admin
	if err := addMember(ctx, mpcMgmtClient, keyID, adminCredID); err != nil {
		log.Fatalf("Failed to bootstrap wallet admin: %v", err)
	}
	log.Println("Wallet admin bootstrapped successfully")

	// 3.2 Add two more team members (and register their passkeys)
	member2 := teamAuthenticator2.CredentialID
	member3 := teamAuthenticator3.CredentialID
	if err := addPasskey(ctx, mpcMgmtClient, member2); err != nil {
		log.Fatalf("Failed to add member2 passkey: %v", err)
	}
	if err := addPasskey(ctx, mpcMgmtClient, member3); err != nil {
		log.Fatalf("Failed to add member3 passkey: %v", err)
	}
	if err := addMemberWithRole(ctx, mpcMgmtClient, keyID, member2, "member"); err != nil {
		log.Fatalf("Failed to add member2 to wallet: %v", err)
	}
	if err := addMemberWithRole(ctx, mpcMgmtClient, keyID, member3, "member"); err != nil {
		log.Fatalf("Failed to add member3 to wallet: %v", err)
	}
	log.Println("Added two team members successfully")

	// 4. Set Signing Policy
	if err := setPolicy2of3(ctx, mpcMgmtClient, keyID); err != nil {
		log.Fatalf("Failed to set policy: %v", err)
	}
	log.Println("Policy set successfully")

	// 5. Team Sign Transaction via gRPC (2 signatures out of 3 members)
	if err := teamSignTransactionGRPC(ctx, signingClient, keyID, []string{adminCredID, member2}); err != nil {
		log.Fatalf("Failed to perform team threshold sign via gRPC: %v", err)
	}
	log.Println("Team threshold signature via gRPC succeeded with 2-of-3")

	log.Println("gRPC System Test Completed Successfully!")
}

// --- Steps ---

func registerNode(ctx context.Context, client infrav1.NodeServiceClient, nodeID string) error {
	req := &infrav1.RegisterNodeRequest{
		DeviceId:  nodeID,
		PublicKey: "mock-pub-key-grpc",
		Type:      "client",
		Version:   "1.0.0",
		Metadata: map[string]string{
			"test": "grpc",
		},
	}
	// Add Metadata for auth if needed? No, RegisterNode is usually public or uses device cert.
	// But we are using mTLS with client cert.
	resp, err := client.RegisterNode(ctx, req)
	if err != nil {
		return err
	}
	log.Printf("Registered Node: %s (Status: %s)", resp.NodeId, resp.Status)
	return nil
}

func createKey(ctx context.Context, client infrav1.KeyServiceClient) (string, error) {
	req := &infrav1.CreateRootKeyRequest{
		Algorithm:  "ECDSA",
		Curve:      "secp256k1",
		Threshold:  2,
		TotalNodes: 3,
		Protocol:   "gg20",
	}
	req.KeyId = fmt.Sprintf("key-%d", time.Now().Unix())

	resp, err := client.CreateRootKey(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Key.KeyId, nil
}

func addPasskey(ctx context.Context, client mpcv1.MPCManagementClient, credID string) error {
	// 根据 credential 选择对应的虚拟设备公钥
	var pubKeyHex string
	var err error
	switch credID {
	case globalAuthenticator.CredentialID:
		pubKeyHex, err = globalAuthenticator.PublicKeyCOSEHex()
	case teamAuthenticator2.CredentialID:
		pubKeyHex, err = teamAuthenticator2.PublicKeyCOSEHex()
	case teamAuthenticator3.CredentialID:
		pubKeyHex, err = teamAuthenticator3.PublicKeyCOSEHex()
	default:
		pubKeyHex, err = globalAuthenticator.PublicKeyCOSEHex()
	}
	if err != nil {
		return err
	}

	// Challenge: credential_id|public_key|device_name
	deviceName := "gRPC Test Device"
	challengeRaw := fmt.Sprintf("%s|%s|%s", credID, pubKeyHex, deviceName)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	reqID := "req-grpc-add-passkey"
	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return err
	}
	token := &mpcv1.AdminAuthToken{
		ReqId:             reqID,
		CredentialId:      authEntry["credential_id"].(string),
		PasskeySignature:  decodeBase64(authEntry["passkey_signature"].(string)),
		AuthenticatorData: decodeBase64(authEntry["authenticator_data"].(string)),
		ClientDataJson:    decodeBase64(authEntry["client_data_json"].(string)),
	}

	req := &mpcv1.AddPasskeyRequest{
		CredentialId: credID,
		PublicKey:    pubKeyHex,
		DeviceName:   deviceName,
		AdminAuth:    token,
	}
	_, err = client.AddPasskey(ctx, req)
	return err
}

func addMember(ctx context.Context, client mpcv1.MPCManagementClient, keyID, credID string) error {
	// Challenge: keyID|credID|role
	challengeRaw := fmt.Sprintf("%s|%s|%s", keyID, credID, "admin")
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	reqID := "req-grpc-add-member"
	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return err
	}

	// AdminAuthToken conversion
	token := &mpcv1.AdminAuthToken{
		ReqId:             reqID,
		CredentialId:      authEntry["credential_id"].(string),
		PasskeySignature:  decodeBase64(authEntry["passkey_signature"].(string)),
		AuthenticatorData: decodeBase64(authEntry["authenticator_data"].(string)),
		ClientDataJson:    decodeBase64(authEntry["client_data_json"].(string)),
	}

	req := &mpcv1.AddWalletMemberRequest{
		WalletId:     keyID,
		CredentialId: credID,
		Role:         "admin",
		AdminAuths:   []*mpcv1.AdminAuthToken{token},
	}
	_, err = client.AddWalletMember(ctx, req)
	return err
}

func addMemberWithRole(ctx context.Context, client mpcv1.MPCManagementClient, keyID, credID, role string) error {
	// Challenge: keyID|credID|role
	challengeRaw := fmt.Sprintf("%s|%s|%s", keyID, credID, role)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	reqID := "req-grpc-add-member"
	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return err
	}
	token := &mpcv1.AdminAuthToken{
		ReqId:             reqID,
		CredentialId:      authEntry["credential_id"].(string),
		PasskeySignature:  decodeBase64(authEntry["passkey_signature"].(string)),
		AuthenticatorData: decodeBase64(authEntry["authenticator_data"].(string)),
		ClientDataJson:    decodeBase64(authEntry["client_data_json"].(string)),
	}
	req := &mpcv1.AddWalletMemberRequest{
		WalletId:     keyID,
		CredentialId: credID,
		Role:         role,
		AdminAuths:   []*mpcv1.AdminAuthToken{token},
	}
	_, err = client.AddWalletMember(ctx, req)
	return err
}

func setPolicy2of3(ctx context.Context, client mpcv1.MPCManagementClient, keyID string) error {
	// Challenge: keyID|policyType|minSignatures
	challengeRaw := fmt.Sprintf("%s|%s|%d", keyID, "team", 2)
	challengeHash := sha256.Sum256([]byte(challengeRaw))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	reqID := "req-grpc-policy"
	authEntry, err := generateAdminAuthForChallenge(reqID, challenge)
	if err != nil {
		return err
	}

	token := &mpcv1.AdminAuthToken{
		ReqId:             reqID,
		CredentialId:      authEntry["credential_id"].(string),
		PasskeySignature:  decodeBase64(authEntry["passkey_signature"].(string)),
		AuthenticatorData: decodeBase64(authEntry["authenticator_data"].(string)),
		ClientDataJson:    decodeBase64(authEntry["client_data_json"].(string)),
	}

	req := &mpcv1.SetSigningPolicyRequest{
		KeyId:         keyID,
		PolicyType:    "team",
		MinSignatures: 2,
		AdminAuths:    []*mpcv1.AdminAuthToken{token},
	}
	_, err = client.SetSigningPolicy(ctx, req)
	return err
}

func signTransaction(ctx context.Context, client infrav1.SigningServiceClient, keyID, credID string) error {
	msg := "Hello gRPC World"
	req := &infrav1.ThresholdSignRequest{
		KeyId:     keyID,
		Message:   []byte(msg),
		ChainType: "ethereum",
	}

	resp, err := client.ThresholdSign(ctx, req)
	if err != nil {
		return err
	}
	if resp.Signature == "" {
		return fmt.Errorf("empty signature received")
	}
	log.Printf("Received Signature: %s (Session: %s)", resp.Signature, resp.SessionId)
	return nil
}

// --- Team Signing using HTTP Infra API (submits two WebAuthn tokens) ---
func teamSignTransaction(keyID string, signerCredIDs []string) error {
	msg := "Hello gRPC Team World"
	challenge := base64.RawURLEncoding.EncodeToString([]byte(msg))

	type authGen struct {
		ReqID        string
		CredentialID string
		Signature    []byte
		AuthData     []byte
		ClientData   []byte
		PublicKeyHex string
	}

	generate := func(auth *Authenticator, reqID string) (*authGen, error) {
		sig, authData, clientData, err := auth.Sign(challenge, baseURL)
		if err != nil {
			return nil, err
		}
		pub, err := auth.PublicKeyCOSEHex()
		if err != nil {
			return nil, err
		}
		return &authGen{
			ReqID:        reqID,
			CredentialID: auth.CredentialID,
			Signature:    sig,
			AuthData:     authData,
			ClientData:   clientData,
			PublicKeyHex: pub,
		}, nil
	}

	var tokens []map[string]interface{}
	for i, cred := range signerCredIDs {
		var auth *Authenticator
		if cred == globalAuthenticator.CredentialID {
			auth = globalAuthenticator
		} else if cred == teamAuthenticator2.CredentialID {
			auth = teamAuthenticator2
		} else if cred == teamAuthenticator3.CredentialID {
			auth = teamAuthenticator3
		} else {
			return fmt.Errorf("unknown credential id in signer list: %s", cred)
		}
		gen, err := generate(auth, fmt.Sprintf("req-team-%d", i+1))
		if err != nil {
			return err
		}
		tokens = append(tokens, map[string]interface{}{
			"req_id":             gen.ReqID,
			"credential_id":      gen.CredentialID,
			"passkey_signature":  base64.StdEncoding.EncodeToString(gen.Signature),
			"authenticator_data": base64.StdEncoding.EncodeToString(gen.AuthData),
			"client_data_json":   base64.StdEncoding.EncodeToString(gen.ClientData),
			"public_key":         gen.PublicKeyHex,
		})
	}

	payload := map[string]interface{}{
		"key_id":       keyID,
		"message":      base64.StdEncoding.EncodeToString([]byte(msg)),
		"message_type": "raw",
		"chain_type":   "ethereum",
		"auth_tokens":  tokens,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", strings.TrimRight(baseURL, "/")+"/api/v1/infra/sign", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Signature string `json:"signature"`
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Signature == "" {
		return fmt.Errorf("empty signature received")
	}
	log.Printf("Team Signature: %s (Session: %s)", out.Signature, out.SessionID)
	return nil
}

func teamSignTransactionGRPC(ctx context.Context, client infrav1.SigningServiceClient, keyID string, signerCredIDs []string) error {
	msg := "Hello gRPC Team World"
	challenge := base64.RawURLEncoding.EncodeToString([]byte(msg))

	type authGen struct {
		ReqID        string
		CredentialID string
		Signature    []byte
		AuthData     []byte
		ClientData   []byte
	}

	generate := func(auth *Authenticator, reqID string) (*authGen, error) {
		sig, authData, clientData, err := auth.Sign(challenge, baseURL)
		if err != nil {
			return nil, err
		}
		return &authGen{
			ReqID:        reqID,
			CredentialID: auth.CredentialID,
			Signature:    sig,
			AuthData:     authData,
			ClientData:   clientData,
		}, nil
	}

	var tokens []*infrav1.AuthToken
	for i, cred := range signerCredIDs {
		var auth *Authenticator
		if cred == globalAuthenticator.CredentialID {
			auth = globalAuthenticator
		} else if cred == teamAuthenticator2.CredentialID {
			auth = teamAuthenticator2
		} else if cred == teamAuthenticator3.CredentialID {
			auth = teamAuthenticator3
		} else {
			return fmt.Errorf("unknown credential id in signer list: %s", cred)
		}
		gen, err := generate(auth, fmt.Sprintf("req-team-%d", i+1))
		if err != nil {
			return err
		}
		tokens = append(tokens, &infrav1.AuthToken{
			PasskeySignature:  gen.Signature,
			AuthenticatorData: gen.AuthData,
			ClientDataJson:    gen.ClientData,
			CredentialId:      gen.CredentialID,
		})
	}

	req := &infrav1.ThresholdSignRequest{
		KeyId:      keyID,
		Message:    []byte(msg),
		MessageHex: hex.EncodeToString([]byte(msg)),
		ChainType:  "ethereum",
		AuthTokens: tokens,
	}
	resp, err := client.ThresholdSign(ctx, req)
	if err != nil {
		return err
	}
	if resp.Signature == "" {
		return fmt.Errorf("empty signature received")
	}
	log.Printf("Team Signature (gRPC): %s (Session: %s)", resp.Signature, resp.SessionId)
	return nil
}

func loadTLSCredentials(certDir string) (credentials.TransportCredentials, error) {
	// Load certificate of the client
	clientCert, err := tls.LoadX509KeyPair(certDir+"/client.crt", certDir+"/client.key")
	if err != nil {
		return nil, err
	}

	// Load CA cert
	caCert, err := os.ReadFile(certDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            certPool,
		InsecureSkipVerify: true, // For self-signed hostnames
	}

	return credentials.NewTLS(config), nil
}

func decodeBase64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// --- Authenticator (Copied & Adapted) ---

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
	clientDataMap := map[string]string{
		"type":      "webauthn.get",
		"challenge": challenge,
		"origin":    origin,
	}
	clientData, err = json.Marshal(clientDataMap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal client data: %w", err)
	}

	rpIDHash := sha256.Sum256([]byte("localhost"))
	flags := byte(0x01) // UP
	counter := []byte{0, 0, 0, 0}
	authData = append(rpIDHash[:], flags)
	authData = append(authData, counter...)

	clientDataHash := sha256.Sum256(clientData)
	signedData := append(authData, clientDataHash[:]...)

	hash := sha256.Sum256(signedData)
	r, s, err := ecdsa.Sign(rand.Reader, a.PrivateKey, hash[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sign: %w", err)
	}

	ecdsaSig := struct {
		R, S *big.Int
	}{R: r, S: s}

	signature, err = asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return signature, authData, clientData, nil
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
