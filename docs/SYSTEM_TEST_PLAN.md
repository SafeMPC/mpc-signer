# MPC Wallet Infrastructure System Test Plan

## 1. Objective
To verify the end-to-end functionality of the MPC Wallet infrastructure in a simulated real-world environment. This test aims to ensure that the core components (Coordinator, Database, API) interact correctly and that the recently implemented features (Member Management, Signing Policy, Passkeys) function as expected.

## 2. Test Environment
*   **Infrastructure**: Docker Compose
    *   `postgres`: Database for persistent storage.
    *   `coordinator`: The main application server (Go) exposing RESTful APIs.
*   **Client**: Custom Go Test Client (Simulating a frontend/admin console).
*   **Protocol**: HTTP/1.1 (REST).

## 3. Test Scope
The system test will cover the following functional areas via RESTful API:

### 3.1 Core Infrastructure
*   **Health/Readiness**: Verify server is up.
*   **Node Management**: Node registration and heartbeat.

### 3.2 Wallet Lifecycle
*   **Key Generation**: Creating a new MPC wallet (Key).
*   **Address Generation**: Deriving blockchain addresses.

### 3.3 Security & Access Control (New Features)
*   **Passkey Management**: Adding FIDO2/WebAuthn passkeys (Mocked).
*   **Member Management**: Adding and removing wallet members (Guardians/Admins).
*   **Signing Policy**:
    *   Setting policy (e.g., 2-of-3 threshold).
    *   Getting policy details.
    *   Enforcing policy during signing (implicitly tested).

### 3.4 Cryptographic Operations
*   **Signing**: Initiating a signing session (Mocking the MPC protocol interaction part, focusing on API flow).
*   **Verification**: Verifying the signature.

## 4. Test Scenario (End-to-End Flow)

The test will execute sequentially:

1.  **Setup**:
    *   Ensure clean database or use unique identifiers.
    *   Wait for `coordinator` to be healthy.

2.  **Execution**:
    *   **Step 1: Register Node**
        *   `POST /infra/nodes` -> Register a compute node (required for key gen).
    *   **Step 2: Create Wallet**
        *   `POST /infra/keys` -> Create a new ECDSA/Ed25519 key.
        *   Store `key_id`.
    *   **Step 3: Add Passkey**
        *   `POST /infra/passkeys` -> Add a passkey credential for a user.
    *   **Step 4: Manage Members**
        *   `POST /infra/wallets/{walletId}/members` -> Add a secondary admin/member.
        *   `DELETE /infra/wallets/{walletId}/members` -> Remove a member (test rollback or separate flow).
    *   **Step 5: Configure Policy**
        *   `PUT /infra/wallets/{walletId}/policy` -> Set `min_signatures` to 2.
        *   `GET /infra/wallets/{walletId}/policy` -> Verify persistence.
    *   **Step 6: Sign Transaction**
        *   `POST /infra/sign` -> Request signature (Note: Without real MPC nodes, this might time out or be mocked to return a pending session).
    *   **Step 7: Verify Signature**
        *   `POST /infra/verify` -> Verify a known signature/message pair (Sanity check).

3.  **Teardown**:
    *   Report results.

## 5. Tools & Deliverables
*   **Test Script**: `scripts/system_test.go` (Go program to execute HTTP requests).
*   **Run Command**: `go run scripts/system_test.go`
