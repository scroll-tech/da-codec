package encoding

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
)

// daChunkV0 groups consecutive DABlocks with their transactions.
type daChunkV0 struct {
	blocks       []DABlock
	transactions [][]*types.TransactionData
}

// newDAChunkV0 is a constructor for daChunkV0, initializing with blocks and transactions.
func newDAChunkV0(blocks []DABlock, transactions [][]*types.TransactionData) *daChunkV0 {
	return &daChunkV0{
		blocks:       blocks,
		transactions: transactions,
	}
}

// Encode serializes the DAChunk into a slice of bytes.
func (c *daChunkV0) Encode() ([]byte, error) {
	if len(c.blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(c.blocks) > 255 {
		return nil, errors.New("number of blocks exceeds 1 byte")
	}

	var chunkBytes []byte
	chunkBytes = append(chunkBytes, byte(len(c.blocks)))

	var l2TxDataBytes []byte

	for _, block := range c.blocks {
		chunkBytes = append(chunkBytes, block.Encode()...)
	}

	for _, blockTxs := range c.transactions {
		for _, txData := range blockTxs {
			if txData.Type == types.L1MessageTxType {
				continue
			}

			var txLen [4]byte
			rlpTxData, err := ConvertTxDataToRLPEncoding(txData, false /* no mock */)
			if err != nil {
				return nil, err
			}
			binary.BigEndian.PutUint32(txLen[:], uint32(len(rlpTxData)))
			l2TxDataBytes = append(l2TxDataBytes, txLen[:]...)
			l2TxDataBytes = append(l2TxDataBytes, rlpTxData...)
		}
	}

	chunkBytes = append(chunkBytes, l2TxDataBytes...)
	return chunkBytes, nil
}

// Hash computes the hash of the DAChunk data.
func (c *daChunkV0) Hash() (common.Hash, error) {
	chunkBytes, err := c.Encode()
	if err != nil {
		return common.Hash{}, err
	}

	if len(chunkBytes) == 0 {
		return common.Hash{}, errors.New("chunk data is empty and cannot be processed")
	}
	numBlocks := chunkBytes[0]

	// concatenate block contexts
	var dataBytes []byte
	for i := 0; i < int(numBlocks); i++ {
		// only the first 58 bytes of each BlockContext are needed for the hashing process
		dataBytes = append(dataBytes, chunkBytes[1+60*i:60*i+59]...)
	}

	// concatenate l1 and l2 tx hashes
	for _, blockTxs := range c.transactions {
		var l1TxHashes []byte
		var l2TxHashes []byte
		for _, txData := range blockTxs {
			txHash := strings.TrimPrefix(txData.TxHash, "0x")
			hashBytes, err := hex.DecodeString(txHash)
			if err != nil {
				return common.Hash{}, fmt.Errorf("failed to decode tx hash from TransactionData: hash=%v, err=%w", txData.TxHash, err)
			}
			if txData.Type == types.L1MessageTxType {
				l1TxHashes = append(l1TxHashes, hashBytes...)
			} else {
				l2TxHashes = append(l2TxHashes, hashBytes...)
			}
		}
		dataBytes = append(dataBytes, l1TxHashes...)
		dataBytes = append(dataBytes, l2TxHashes...)
	}

	hash := crypto.Keccak256Hash(dataBytes)
	return hash, nil
}

// BlockRange returns the block range of the DAChunk.
func (c *daChunkV0) BlockRange() (uint64, uint64, error) {
	if len(c.blocks) == 0 {
		return 0, 0, errors.New("number of blocks is 0")
	}

	return c.blocks[0].Number(), c.blocks[len(c.blocks)-1].Number(), nil
}

// daChunkV1 groups consecutive DABlocks with their transactions.
type daChunkV1 daChunkV0

// newDAChunkV1 is a constructor for daChunkV1, initializing with blocks and transactions.
func newDAChunkV1(blocks []DABlock, transactions [][]*types.TransactionData) *daChunkV1 {
	return &daChunkV1{
		blocks:       blocks,
		transactions: transactions,
	}
}

// Encode serializes the DAChunk into a slice of bytes.
func (c *daChunkV1) Encode() ([]byte, error) {
	var chunkBytes []byte
	chunkBytes = append(chunkBytes, byte(len(c.blocks)))

	for _, block := range c.blocks {
		blockBytes := block.Encode()
		chunkBytes = append(chunkBytes, blockBytes...)
	}

	return chunkBytes, nil
}

// Hash computes the hash of the DAChunk data.
func (c *daChunkV1) Hash() (common.Hash, error) {
	var dataBytes []byte

	// concatenate block contexts
	for _, block := range c.blocks {
		encodedBlock := block.Encode()
		// only the first 58 bytes are used in the hashing process
		dataBytes = append(dataBytes, encodedBlock[:58]...)
	}

	// concatenate l1 tx hashes
	for _, blockTxs := range c.transactions {
		for _, txData := range blockTxs {
			if txData.Type != types.L1MessageTxType {
				continue
			}

			txHash := strings.TrimPrefix(txData.TxHash, "0x")
			hashBytes, err := hex.DecodeString(txHash)
			if err != nil {
				return common.Hash{}, err
			}
			if len(hashBytes) != 32 {
				return common.Hash{}, fmt.Errorf("unexpected hash: %s", txData.TxHash)
			}
			dataBytes = append(dataBytes, hashBytes...)
		}
	}

	hash := crypto.Keccak256Hash(dataBytes)
	return hash, nil
}

// BlockRange returns the block range of the DAChunk.
func (c *daChunkV1) BlockRange() (uint64, uint64, error) {
	if len(c.blocks) == 0 {
		return 0, 0, errors.New("number of blocks is 0")
	}

	return c.blocks[0].Number(), c.blocks[len(c.blocks)-1].Number(), nil
}

// DAChunkRawTx groups consecutive DABlocks with their L2 transactions, L1 msgs are loaded in another place.
type DAChunkRawTx struct {
	Blocks       []DABlock
	Transactions []types.Transactions
}
