package chain

import (
	"math/big"
)

// BuildTxRequest 描述构建交易所需的通用参数
type BuildTxRequest struct {
	From    string
	To      string
	Amount  *big.Int
	Nonce   uint64
	FeeRate uint64
	Data    []byte
}

// Transaction 统一封装原始交易和其哈希
type Transaction struct {
	Raw  string
	Hash string
}

// Adapter 定义链适配器需要实现的最小能力
type Adapter interface {
	GenerateAddress(pubKey []byte) (string, error)
	BuildTransaction(req *BuildTxRequest) (*Transaction, error)
}
