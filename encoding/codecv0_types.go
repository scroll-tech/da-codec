package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// daBlockV0 represents a Data Availability Block.
type daBlockV0 struct {
	number          uint64
	timestamp       uint64
	baseFee         *big.Int
	gasLimit        uint64
	numTransactions uint16
	numL1Messages   uint16
}

// newDABlockV0 is a constructor function for daBlockV0 that initializes the internal fields.
func newDABlockV0(number uint64, timestamp uint64, baseFee *big.Int, gasLimit uint64, numTransactions uint16, numL1Messages uint16) *daBlockV0 {
	return &daBlockV0{
		number:          number,
		timestamp:       timestamp,
		baseFee:         baseFee,
		gasLimit:        gasLimit,
		numTransactions: numTransactions,
		numL1Messages:   numL1Messages,
	}
}

// Encode serializes the DABlock into a slice of bytes.
func (b *daBlockV0) Encode() []byte {
	bytes := make([]byte, blockContextByteSize)
	binary.BigEndian.PutUint64(bytes[0:], b.number)
	binary.BigEndian.PutUint64(bytes[8:], b.timestamp)
	if b.baseFee != nil {
		binary.BigEndian.PutUint64(bytes[40:], b.baseFee.Uint64())
	}
	binary.BigEndian.PutUint64(bytes[48:], b.gasLimit)
	binary.BigEndian.PutUint16(bytes[56:], b.numTransactions)
	binary.BigEndian.PutUint16(bytes[58:], b.numL1Messages)
	return bytes
}

// Decode populates the fields of a DABlock from a byte slice.
func (b *daBlockV0) Decode(bytes []byte) error {
	if len(bytes) != blockContextByteSize {
		return errors.New("block encoding is not blockContextByteSize bytes long")
	}

	b.number = binary.BigEndian.Uint64(bytes[0:8])
	b.timestamp = binary.BigEndian.Uint64(bytes[8:16])
	b.baseFee = new(big.Int).SetUint64(binary.BigEndian.Uint64(bytes[40:48]))
	b.gasLimit = binary.BigEndian.Uint64(bytes[48:56])
	b.numTransactions = binary.BigEndian.Uint16(bytes[56:58])
	b.numL1Messages = binary.BigEndian.Uint16(bytes[58:60])

	return nil
}

// Number returns the block number.
func (b *daBlockV0) Number() uint64 {
	return b.number
}

// Timestamp returns the block timestamp.
func (b *daBlockV0) Timestamp() uint64 {
	return b.timestamp
}

// BaseFee returns the block base fee.
func (b *daBlockV0) BaseFee() *big.Int {
	return b.baseFee
}

// GasLimit returns the block gas limit.
func (b *daBlockV0) GasLimit() uint64 {
	return b.gasLimit
}

// NumTransactions returns the number of transactions in the block.
func (b *daBlockV0) NumTransactions() uint16 {
	return b.numTransactions
}

// NumL1Messages returns the number of L1 messages in the block.
func (b *daBlockV0) NumL1Messages() uint16 {
	return b.numL1Messages
}

// DAChunkRawTx groups consecutive DABlocks with their L2 transactions, L1 msgs are loaded in another place.
type DAChunkRawTx struct {
	Blocks       []DABlock
	Transactions []types.Transactions
}

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

	if len(c.blocks) > math.MaxUint8 {
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
			rlpTxData, err := convertTxDataToRLPEncoding(txData, false /* no mock */)
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
			hashBytes := common.FromHex(txData.TxHash)
			if len(hashBytes) != common.HashLength {
				return common.Hash{}, fmt.Errorf("unexpected hash: %s", txData.TxHash)
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

// daBatchV0 contains metadata about a batch of DAChunks.
type daBatchV0 struct {
	version                uint8
	batchIndex             uint64
	l1MessagePopped        uint64
	totalL1MessagePopped   uint64
	dataHash               common.Hash
	parentBatchHash        common.Hash
	skippedL1MessageBitmap []byte
}

// newDABatchV0 is a constructor for daBatchV0.
func newDABatchV0(version uint8, batchIndex, l1MessagePopped, totalL1MessagePopped uint64, dataHash, parentBatchHash common.Hash, skippedL1MessageBitmap []byte) *daBatchV0 {
	return &daBatchV0{
		version:                version,
		batchIndex:             batchIndex,
		l1MessagePopped:        l1MessagePopped,
		totalL1MessagePopped:   totalL1MessagePopped,
		dataHash:               dataHash,
		parentBatchHash:        parentBatchHash,
		skippedL1MessageBitmap: skippedL1MessageBitmap,
	}
}

// Encode serializes the DABatch into bytes.
func (b *daBatchV0) Encode() []byte {
	batchBytes := make([]byte, 89+len(b.skippedL1MessageBitmap))
	batchBytes[0] = b.version
	binary.BigEndian.PutUint64(batchBytes[1:], b.batchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:], b.l1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:], b.totalL1MessagePopped)
	copy(batchBytes[25:], b.dataHash[:])
	copy(batchBytes[57:], b.parentBatchHash[:])
	copy(batchBytes[89:], b.skippedL1MessageBitmap[:])
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *daBatchV0) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// Blob returns the blob of the batch.
func (b *daBatchV0) Blob() *kzg4844.Blob {
	return nil
}

// BlobBytes returns the blob bytes of the batch.
func (b *daBatchV0) BlobBytes() []byte {
	return nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *daBatchV0) BlobDataProofForPointEvaluation() ([]byte, error) {
	return nil, nil
}

// Version returns the version of the DABatch.
func (b *daBatchV0) Version() CodecVersion {
	return CodecVersion(b.version)
}

// SkippedL1MessageBitmap returns the skipped L1 message bitmap of the DABatch.
func (b *daBatchV0) SkippedL1MessageBitmap() []byte {
	return b.skippedL1MessageBitmap
}

// DataHash returns the data hash of the DABatch.
func (b *daBatchV0) DataHash() common.Hash {
	return b.dataHash
}
