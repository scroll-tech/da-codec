package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
)

type DACodecV0 struct{}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (o *DACodecV0) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (*DABlock, error) {
	if !block.Header.Number.IsUint64() {
		return nil, errors.New("block number is not uint64")
	}

	// note: numL1Messages includes skipped messages
	numL1Messages := block.NumL1Messages(totalL1MessagePoppedBefore)
	if numL1Messages > math.MaxUint16 {
		return nil, errors.New("number of L1 messages exceeds max uint16")
	}

	// note: numTransactions includes skipped messages
	numL2Transactions := block.NumL2Transactions()
	numTransactions := numL1Messages + numL2Transactions
	if numTransactions > math.MaxUint16 {
		return nil, errors.New("number of transactions exceeds max uint16")
	}

	daBlock := &DABlock{
		BlockNumber:     block.Header.Number.Uint64(),
		Timestamp:       block.Header.Time,
		BaseFee:         block.Header.BaseFee,
		GasLimit:        block.Header.GasLimit,
		NumTransactions: uint16(numTransactions),
		NumL1Messages:   uint16(numL1Messages),
	}

	return daBlock, nil
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (o *DACodecV0) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	var blocks []*DABlock
	var txs [][]*types.TransactionData

	if chunk == nil {
		return nil, errors.New("chunk is nil")
	}

	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > 255 {
		return nil, errors.New("number of blocks exceeds 1 byte")
	}

	for _, block := range chunk.Blocks {
		b, err := o.NewDABlock(block, totalL1MessagePoppedBefore)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
		totalL1MessagePoppedBefore += block.NumL1Messages(totalL1MessagePoppedBefore)
		txs = append(txs, block.Transactions)
	}

	daChunk := DAChunkV0{
		Blocks:       blocks,
		Transactions: txs,
	}

	return &daChunk, nil
}

// NewDABatch creates a DABatch from the provided Batch.
func (o *DACodecV0) NewDABatch(batch *Batch) (DABatch, error) {
	// compute batch data hash
	var dataBytes []byte
	totalL1MessagePoppedBeforeChunk := batch.TotalL1MessagePoppedBefore

	for _, chunk := range batch.Chunks {
		// build data hash
		daChunk, err := o.NewDAChunk(chunk, totalL1MessagePoppedBeforeChunk)
		if err != nil {
			return nil, err
		}
		totalL1MessagePoppedBeforeChunk += chunk.NumL1Messages(totalL1MessagePoppedBeforeChunk)
		daChunkHash, err := daChunk.Hash()
		if err != nil {
			return nil, err
		}
		dataBytes = append(dataBytes, daChunkHash.Bytes()...)
	}

	// compute data hash
	dataHash := crypto.Keccak256Hash(dataBytes)

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	daBatch := DABatchV0{
		DABatchBase: DABatchBase{
			Version:                uint8(CodecV0),
			BatchIndex:             batch.Index,
			L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
			TotalL1MessagePopped:   totalL1MessagePoppedAfter,
			DataHash:               dataHash,
			ParentBatchHash:        batch.ParentBatchHash,
			SkippedL1MessageBitmap: bitmapBytes,
		},
	}

	return &daBatch, nil
}

// NewDABatchWithExpectedBlobVersionedHashes creates a DABatch from the provided Batch.
// It also checks if the blob versioned hashes are as expected.
func (o *DACodecV0) NewDABatchWithExpectedBlobVersionedHashes(batch *Batch, hashes []common.Hash) (DABatch, error) {
	daBatch, err := o.NewDABatch(batch)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(daBatch.BlobVersionedHashes(), hashes) {
		return nil, fmt.Errorf("blob versioned hashes do not match. Expected: %v, Got: %v", hashes, daBatch.BlobVersionedHashes())
	}

	return daBatch, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
func (o *DACodecV0) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 89 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 89 bytes but got %d", len(data))
	}

	b := &DABatchV0{
		DABatchBase: DABatchBase{
			Version:                data[0],
			BatchIndex:             binary.BigEndian.Uint64(data[1:9]),
			L1MessagePopped:        binary.BigEndian.Uint64(data[9:17]),
			TotalL1MessagePopped:   binary.BigEndian.Uint64(data[17:25]),
			DataHash:               common.BytesToHash(data[25:57]),
			ParentBatchHash:        common.BytesToHash(data[57:89]),
			SkippedL1MessageBitmap: data[89:],
		},
	}

	return b, nil
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
func (o *DACodecV0) EstimateBlockL1CommitCalldataSize(b *Block) (uint64, error) {
	var size uint64
	for _, txData := range b.Transactions {
		if txData.Type == types.L1MessageTxType {
			continue
		}
		size += 4 // 4 bytes payload length
		txPayloadLength, err := getTxPayloadLength(txData)
		if err != nil {
			return 0, err
		}
		size += txPayloadLength
	}
	size += 60 // 60 bytes BlockContext
	return size, nil
}

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func (o *DACodecV0) EstimateBlockL1CommitGas(b *Block) (uint64, error) {
	var total uint64
	var numL1Messages uint64
	for _, txData := range b.Transactions {
		if txData.Type == types.L1MessageTxType {
			numL1Messages++
			continue
		}

		txPayloadLength, err := getTxPayloadLength(txData)
		if err != nil {
			return 0, err
		}
		total += CalldataNonZeroByteGas * txPayloadLength // an over-estimate: treat each byte as non-zero
		total += CalldataNonZeroByteGas * 4               // 4 bytes payload length
		total += GetKeccak256Gas(txPayloadLength)         // l2 tx hash
	}

	// 60 bytes BlockContext calldata
	total += CalldataNonZeroByteGas * 60

	// sload
	total += 2100 * numL1Messages // numL1Messages times cold sload in L1MessageQueue

	// staticcall
	total += 100 * numL1Messages // numL1Messages times call to L1MessageQueue
	total += 100 * numL1Messages // numL1Messages times warm address access to L1MessageQueue

	total += GetMemoryExpansionCost(36) * numL1Messages // staticcall to proxy
	total += 100 * numL1Messages                        // read admin in proxy
	total += 100 * numL1Messages                        // read impl in proxy
	total += 100 * numL1Messages                        // access impl
	total += GetMemoryExpansionCost(36) * numL1Messages // delegatecall to impl

	return total, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (o *DACodecV0) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	var totalL1CommitCalldataSize uint64
	for _, block := range c.Blocks {
		blockL1CommitCalldataSize, err := o.EstimateBlockL1CommitCalldataSize(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += blockL1CommitCalldataSize
	}
	return totalL1CommitCalldataSize, nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (o *DACodecV0) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	var totalTxNum uint64
	var totalL1CommitGas uint64
	for _, block := range c.Blocks {
		totalTxNum += uint64(len(block.Transactions))
		blockL1CommitGas, err := o.EstimateBlockL1CommitGas(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += blockL1CommitGas
	}

	numBlocks := uint64(len(c.Blocks))
	totalL1CommitGas += 100 * numBlocks                         // numBlocks times warm sload
	totalL1CommitGas += CalldataNonZeroByteGas                  // numBlocks field of chunk encoding in calldata
	totalL1CommitGas += CalldataNonZeroByteGas * numBlocks * 60 // numBlocks of BlockContext in chunk

	totalL1CommitGas += GetKeccak256Gas(58*numBlocks + 32*totalTxNum) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (o *DACodecV0) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	var totalL1CommitGas uint64

	// Add extra gas costs
	totalL1CommitGas += 100000                 // constant to account for ops like _getAdmin, _implementation, _requireNotPaused, etc
	totalL1CommitGas += 4 * 2100               // 4 one-time cold sload for commitBatch
	totalL1CommitGas += 20000                  // 1 time sstore
	totalL1CommitGas += 21000                  // base fee for tx
	totalL1CommitGas += CalldataNonZeroByteGas // version in calldata

	// adjusting gas:
	// add 1 time cold sload (2100 gas) for L1MessageQueue
	// add 1 time cold address access (2600 gas) for L1MessageQueue
	// minus 1 time warm sload (100 gas) & 1 time warm address access (100 gas)
	totalL1CommitGas += (2100 + 2600 - 100 - 100)
	totalL1CommitGas += GetKeccak256Gas(89 + 32)           // parent batch header hash, length is estimated as 89 (constant part)+ 32 (1 skippedL1MessageBitmap)
	totalL1CommitGas += CalldataNonZeroByteGas * (89 + 32) // parent batch header in calldata

	// adjust batch data hash gas cost
	totalL1CommitGas += GetKeccak256Gas(uint64(32 * len(b.Chunks)))

	totalL1MessagePoppedBefore := b.TotalL1MessagePoppedBefore

	for _, chunk := range b.Chunks {
		chunkL1CommitGas, err := o.EstimateChunkL1CommitGas(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += chunkL1CommitGas

		totalL1MessagePoppedInChunk := chunk.NumL1Messages(totalL1MessagePoppedBefore)
		totalL1MessagePoppedBefore += totalL1MessagePoppedInChunk

		totalL1CommitGas += CalldataNonZeroByteGas * (32 * (totalL1MessagePoppedInChunk + 255) / 256)
		totalL1CommitGas += GetKeccak256Gas(89 + 32*(totalL1MessagePoppedInChunk+255)/256)

		totalL1CommitCalldataSize, err := o.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += GetMemoryExpansionCost(totalL1CommitCalldataSize)
	}

	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (o *DACodecV0) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	var totalL1CommitCalldataSize uint64
	for _, chunk := range b.Chunks {
		chunkL1CommitCalldataSize, err := o.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += chunkL1CommitCalldataSize
	}
	return totalL1CommitCalldataSize, nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func (o *DACodecV0) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (o *DACodecV0) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	return true, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (o *DACodecV0) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	return 0, 0, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (o *DACodecV0) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	return 0, 0, nil
}

// SetCompression enables or disables compression.
func (o *DACodecV0) SetCompression(enable bool) {}
