package node

import "time"

// Node 节点信息
type Node struct {
	NodeID        string
	NodeType      string // service, signer, client
	Purpose       string // signing, backup
	Endpoint      string
	PublicKey     string
	Status        string // active, inactive, faulty
	Capabilities  []string
	Metadata      map[string]interface{}
	RegisteredAt  time.Time
	LastHeartbeat *time.Time
}

// NodeStatus 节点状态
type NodeStatus string

const (
	NodeStatusActive   NodeStatus = "active"
	NodeStatusInactive NodeStatus = "inactive"
	NodeStatusFaulty   NodeStatus = "faulty"
)

// NodeType 节点类型
type NodeType string

const (
	NodeTypeService NodeType = "service" // MPC Service (会话管理/协调，不参与计算)
	NodeTypeSigner  NodeType = "signer"   // Signer 节点 (参与 MPC 协议计算)
	NodeTypeClient  NodeType = "client"   // 客户端节点
)

// NodePurpose 节点用途
type NodePurpose string

const (
	NodePurposeSigning NodePurpose = "signing" // 参与签名
	NodePurposeBackup  NodePurpose = "backup"  // 仅用于备份
)

// HealthCheck 健康检查结果
type HealthCheck struct {
	NodeID    string
	Status    string
	Timestamp time.Time
	Checks    map[string]string
	Metrics   map[string]float64
}
