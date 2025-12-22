package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	pb "github.com/kashguard/go-mpc-infra/mpc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// This example demonstrates how to use the MPC Management API and Signing API.
//
// 1. Connect to the gRPC server.
// 2. Add a User Auth Key (Management API).
// 3. Set a Signing Policy (Management API).
// 4. Perform a Transaction Signing (Signing API) using the registered key.

func main() {
	// 0. Configuration
	serverAddr := "localhost:9090" // Adjust port if needed
	keyID := "test-wallet-123"

	// 1. Connect to gRPC Server
	// In production, use credentials.NewClientTLSFromFile for secure connection
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	mgmtClient := pb.NewMPCManagementClient(conn)
	nodeClient := pb.NewMPCNodeClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ---------------------------------------------------------
	// Step A: Client Key Generation (Client Side)
	// ---------------------------------------------------------
	// The client needs its own key pair to sign requests.
	// Here we generate a new Ed25519 key pair for demonstration.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}
	pubKeyHex := hex.EncodeToString(pubKey)
	fmt.Printf("Generated Client Public Key: %s\n", pubKeyHex)

	// ---------------------------------------------------------
	// Step B: Register Key & Policy (Management API)
	// ---------------------------------------------------------
	// Note: These calls do NOT require a signature in the current implementation.
	// Access control should be handled via mTLS or network restrictions.

	// 1. Add User Passkey
	fmt.Println("\n[Management] Adding User Passkey...")
	addKeyResp, err := mgmtClient.AddUserPasskey(ctx, &pb.AddUserPasskeyRequest{
		CredentialId: "cred-" + keyID,
		PublicKey:    pubKeyHex,
		UserId:       "AdminUser",
		DeviceName:   "Demo Device",
		AdminAuth:    nil,
	})
	if err != nil {
		// Note: This might fail if the server is not running or keyID is invalid in DB
		log.Printf("Error calling AddUserAuthKey: %v", err)
		log.Println("Ensure the server is running and database is connected.")
		// We continue to show the flow, but in reality we'd stop here.
	} else {
		fmt.Printf("Success: %v, Message: %s\n", addKeyResp.Success, addKeyResp.Message)
	}

	// 2. Set Signing Policy
	fmt.Println("\n[Management] Setting Signing Policy...")
	setPolicyResp, err := mgmtClient.SetSigningPolicy(ctx, &pb.SetSigningPolicyRequest{
		KeyId:         keyID,
		PolicyType:    "single", // or "team"
		MinSignatures: 1,        // Number of valid signatures required
	})
	if err != nil {
		log.Printf("Error calling SetSigningPolicy: %v", err)
	} else {
		fmt.Printf("Success: %v, Message: %s\n", setPolicyResp.Success, setPolicyResp.Message)
	}

	// ---------------------------------------------------------
	// Step C: Perform Signing (Signing API)
	// ---------------------------------------------------------
	// Now we want to sign a transaction using the MPC wallet.
	// We must provide a valid signature from our registered User Auth Key.

	// 1. Prepare Message (Transaction Hash)
	msg := []byte("transaction_data_hash")
	msgHex := hex.EncodeToString(msg)

	// 2. Sign the message with Client Private Key
	// This proves we are the authorized user.
	signature := ed25519.Sign(privKey, msg)
	fmt.Printf("\n[Client] Signed request with client private key. Signature len: %d\n", len(signature))

	// 3. Call StartSign
	fmt.Println("\n[Signing] Requesting MPC Signature...")
	signResp, err := nodeClient.StartSign(ctx, &pb.StartSignRequest{
		KeyId:      keyID,
		MessageHex: msgHex, // The message to be signed by MPC
		AuthTokens: []*pb.StartSignRequest_AuthToken{
			{
				PublicKey: pubKeyHex, // Who is signing
				Signature: signature, // The proof
			},
		},
	})

	if err != nil {
		log.Printf("Error calling StartSign: %v", err)
	} else {
		fmt.Printf("StartSign Response: Started=%v, Message=%s\n", signResp.Started, signResp.Message)
	}
}
