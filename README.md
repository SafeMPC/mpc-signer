# MPC Signer Node

> MPC Signing Node - Node executing MPC protocol computations (Pure gRPC Service)

> **[中文版](READMECN.md) | English**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](go.mod)

**mpc-signer** is the signing node in the MPC wallet system, responsible for executing MPC protocol computations (DKG and threshold signing).

---

## 🎯 Node Responsibilities

### Core Functions
- ✅ **Execute MPC Protocols**: Participate in DKG (Distributed Key Generation) and threshold signature protocols
- ✅ **Store Key Shards**: Securely store P2 key shards (encrypted storage in Nitro Enclave)
- ✅ **gRPC Service**: Receive requests from mpc-service
- ✅ **Protocol Support**: Support GG20 (ECDSA) and FROST (EdDSA) protocols

### What It Doesn't Do
- ❌ **REST API**: No HTTP API provided
- ❌ **User Authentication**: User authentication is handled by Service
- ❌ **Direct Client Access**: Does not accept direct requests from clients

---

## 🏗️ Architecture

### Communication Pattern

```
Client (P1)
    │
    │ REST + WebSocket
    │
    ▼
Service (mpc-service)
    │
    │ gRPC + mTLS + Service Token
    │
    ▼
Signer (mpc-signer)
    │
    │ Private Network TEE
    │ AWS Nitro Enclave
```

### 2-of-2 Mode
- **Client-side P1**: Acts as Signer node (relayed through Service)
- **Server-side P2**: This service

mpc-signer focuses solely on executing MPC protocol computations. Session management, API services, and other coordination tasks are handled by mpc-service nodes.

---

## 🔌 gRPC Interface

### SignerService

```protobuf
service SignerService {
  // DKG related
  rpc StartDKG(StartDKGRequest) returns (StartDKGResponse);
  rpc GetDKGStatus(GetDKGStatusRequest) returns (DKGStatusResponse);
  
  // Signing related
  rpc StartSign(StartSignRequest) returns (StartSignResponse);
  rpc GetSignStatus(GetSignStatusRequest) returns (SignStatusResponse);
  
  // Protocol message handling
  rpc SubmitProtocolMessage(ProtocolMessageRequest) returns (ProtocolMessageResponse);
  
  // Health check
  rpc Ping(PingRequest) returns (PongResponse);
}
```

**Full Definition**: See `proto/mpc/v1/signer.proto`

---

## 🔒 Security Mechanisms

### 1. Network Isolation
- Deployed in **AWS VPC Private Subnet**
- No public ports exposed
- Only accepts connections from Service via private network

### 2. mTLS Authentication
```yaml
grpc:
  tls_enabled: true
  cert_file: "/app/certs/signer.crt"
  key_file: "/app/certs/signer.key"
  ca_cert: "/app/certs/ca.crt"
  client_auth: "require"  # Client certificate required
```

### 3. Service Token Validation
- Validates JWT tokens from Service
- Checks token audience, issuer, and expiration
- Rejects unauthorized requests

### 4. Message Signature Verification
- Validates HMAC signatures on protocol messages
- Prevents message tampering
- Ensures messages originate from trusted Service

---

## 🚀 Quick Start

### Requirements
- Go 1.21+
- Docker & Docker Compose
- Network connectivity to mpc-service

### Launch Service

```bash
cd mpc-signer
docker compose up -d server-signer-p2
```

### Configuration

Signer connects to Service infrastructure via environment variables:

```yaml
MPC_NODE_TYPE: "signer"
MPC_NODE_ID: "server-signer-p2"
MPC_SERVICE_ENDPOINT: "host.docker.internal:9090"
MPC_CONSUL_ADDRESS: "host.docker.internal:8500"
PGHOST: "host.docker.internal"
MPC_REDIS_ENDPOINT: "host.docker.internal:6379"
```

### Health Check

```bash
# gRPC health check
grpcurl -plaintext localhost:9091 mpc.v1.SignerService/Ping
```

---

## 📁 Directory Structure

```
mpc-signer/
├── internal/
│   ├── config/              # Configuration management
│   ├── infra/
│   │   ├── signing/        # Signing service
│   │   ├── dkg/            # DKG service
│   │   ├── session/        # Session management
│   │   └── storage/        # Key shard storage
│   └── mpc/
│       ├── protocol/        # Protocol engine (GG20/FROST)
│       ├── grpc/            # gRPC Server (core)
│       ├── node/            # Node management
│       └── chain/           # Chain adapters
├── proto/mpc/v1/           # gRPC definitions
├── pb/mpc/v1/              # Generated pb files
├── main.go                 # Entry point
└── docker-compose.yml      # Docker configuration
```

**Note**: No `api/` or `handlers/` directories!

---

## 🔧 Development

### Build
```bash
make build
```

### Test
```bash
make test
```

### Access Container
```bash
docker compose exec server-signer-p2 bash
```

---

## 📖 Related Documentation

- [V2 Architecture Design](../design/docs/ARCHITECTURE_V2.md)
- [Interface Design](../design/docs/INTERFACE_DESIGN.md)
- [Development Standards](../.cursorrules)
- [Service Node](../mpc-service/README.md)

---

## ⚠️ Important Notes

### Signer is a Pure Backend Service
- No user interface
- No REST API
- Communicates with Service via gRPC only

### Deployment Recommendations
- AWS Nitro Enclave
- VPC Private Subnet
- Connect to Service via VPN or AWS PrivateLink

---

**Signer = gRPC Server + MPC Computation Engine** 🔐
