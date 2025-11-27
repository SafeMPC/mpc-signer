package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ripemd160"
)

// BitcoinAdapter 基于 btcsuite 的简单实现
type BitcoinAdapter struct {
	params *chaincfg.Params
}

// NewBitcoinAdapter 创建一个 Bitcoin 适配器
func NewBitcoinAdapter(params *chaincfg.Params) *BitcoinAdapter {
	if params == nil {
		params = &chaincfg.MainNetParams
	}
	return &BitcoinAdapter{params: params}
}

// GenerateAddress 根据公钥生成 P2PKH 地址
func (a *BitcoinAdapter) GenerateAddress(pubKey []byte) (string, error) {
	if len(pubKey) == 0 {
		return "", errors.New("public key is required")
	}

	sha := sha256.Sum256(pubKey)
	ripemd := ripemd160.New()
	if _, err := ripemd.Write(sha[:]); err != nil {
		return "", errors.Wrap(err, "failed to hash public key")
	}
	hash160 := ripemd.Sum(nil)
	return fmt.Sprintf("btc-%s", hex.EncodeToString(hash160)), nil
}

// BuildTransaction 构建一个简单的原始交易描述并返回双哈希
func (a *BitcoinAdapter) BuildTransaction(req *BuildTxRequest) (*Transaction, error) {
	if req == nil {
		return nil, errors.New("build request is nil")
	}
	if req.Amount == nil {
		return nil, errors.New("amount is required")
	}

	raw := fmt.Sprintf(
		"btc-tx|from:%s|to:%s|amount:%s|nonce:%d|feerate:%d|data:%s",
		req.From,
		req.To,
		req.Amount.String(),
		req.Nonce,
		req.FeeRate,
		hex.EncodeToString(req.Data),
	)

	hash := chainhash.DoubleHashH([]byte(raw)).String()
	return &Transaction{
		Raw:  raw,
		Hash: hash,
	}, nil
}
