package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

type DACodecV0 struct{}

// codecv0MaxNumChunks is the maximum number of chunks that a batch can contain.
const codecv0MaxNumChunks = 15

// Version returns the codec version.
func (d *DACodecV0) Version() CodecVersion {
	return CodecV0
}

// MaxNumChunksPerBatch returns the maximum number of chunks per batch.
func (d *DACodecV0) MaxNumChunksPerBatch() uint64 {
	return codecv0MaxNumChunks
}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (d *DACodecV0) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (DABlock, error) {
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

	daBlock := newDABlockV0(
		block.Header.Number.Uint64(), // number
		block.Header.Time,            // timestamp
		block.Header.BaseFee,         // baseFee
		block.Header.GasLimit,        // gasLimit
		uint16(numTransactions),      // numTransactions
		uint16(numL1Messages),        // numL1Messages
	)

	return daBlock, nil
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (d *DACodecV0) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	var blocks []DABlock
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
		b, err := d.NewDABlock(block, totalL1MessagePoppedBefore)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
		totalL1MessagePoppedBefore += block.NumL1Messages(totalL1MessagePoppedBefore)
		txs = append(txs, block.Transactions)
	}

	daChunk := newDAChunkV0(
		blocks, // blocks
		txs,    // transactions
	)

	return daChunk, nil
}

// DecodeDAChunksRawTx takes a byte slice and decodes it into a []*DAChunkRawTx.
func (d *DACodecV0) DecodeDAChunksRawTx(chunkBytes [][]byte) ([]*DAChunkRawTx, error) {
	var chunks []*DAChunkRawTx
	for _, chunk := range chunkBytes {
		if len(chunk) < 1 {
			return nil, fmt.Errorf("invalid chunk, length is less than 1")
		}

		numBlocks := int(chunk[0])
		if len(chunk) < 1+numBlocks*blockContextByteSize {
			return nil, fmt.Errorf("chunk size doesn't match with numBlocks, byte length of chunk: %v, expected length: %v", len(chunk), 1+numBlocks*blockContextByteSize)
		}

		blocks := make([]DABlock, numBlocks)
		for i := 0; i < numBlocks; i++ {
			startIdx := 1 + i*blockContextByteSize // add 1 to skip numBlocks byte
			endIdx := startIdx + blockContextByteSize
			blocks[i] = &daBlockV0{}
			err := blocks[i].Decode(chunk[startIdx:endIdx])
			if err != nil {
				return nil, err
			}
		}

		var transactions []types.Transactions
		currentIndex := 1 + numBlocks*blockContextByteSize
		for _, block := range blocks {
			var blockTransactions types.Transactions
			// ignore L1 msg transactions from the block, consider only L2 transactions
			txNum := int(block.NumTransactions() - block.NumL1Messages())
			for i := 0; i < txNum; i++ {
				if len(chunk) < currentIndex+txLenByteSize {
					return nil, fmt.Errorf("chunk size doesn't match, next tx size is less then 4, byte length of chunk: %v, expected minimum length: %v, txNum without l1 msgs: %d", len(chunk), currentIndex+txLenByteSize, i)
				}
				txLen := int(binary.BigEndian.Uint32(chunk[currentIndex : currentIndex+txLenByteSize]))
				if len(chunk) < currentIndex+txLenByteSize+txLen {
					return nil, fmt.Errorf("chunk size doesn't match with next tx length, byte length of chunk: %v, expected minimum length: %v, txNum without l1 msgs: %d", len(chunk), currentIndex+txLenByteSize+txLen, i)
				}
				txData := chunk[currentIndex+txLenByteSize : currentIndex+txLenByteSize+txLen]
				tx := &types.Transaction{}
				err := tx.UnmarshalBinary(txData)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal tx, pos of tx in chunk bytes: %d. tx num without l1 msgs: %d, err: %w", currentIndex, i, err)
				}
				blockTransactions = append(blockTransactions, tx)
				currentIndex += txLenByteSize + txLen
			}
			transactions = append(transactions, blockTransactions)
		}

		chunks = append(chunks, &DAChunkRawTx{
			Blocks:       blocks,
			Transactions: transactions,
		})
	}
	return chunks, nil
}

// DecodeTxsFromBlob decodes txs from blob bytes and writes to chunks
func (d *DACodecV0) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	return nil
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV0) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > int(d.MaxNumChunksPerBatch()) {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	// compute batch data hash
	var dataBytes []byte
	totalL1MessagePoppedBeforeChunk := batch.TotalL1MessagePoppedBefore

	for _, chunk := range batch.Chunks {
		// build data hash
		daChunk, err := d.NewDAChunk(chunk, totalL1MessagePoppedBeforeChunk)
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
	bitmapBytes, totalL1MessagePoppedAfter, err := ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	daBatch := newDABatchV0(
		uint8(CodecV0), // version
		batch.Index,    // batchIndex
		totalL1MessagePoppedAfter-batch.TotalL1MessagePoppedBefore, // l1MessagePopped
		totalL1MessagePoppedAfter,                                  // totalL1MessagePopped
		dataHash,                                                   // dataHash
		batch.ParentBatchHash,                                      // parentBatchHash
		bitmapBytes,                                                // skippedL1MessageBitmap
	)

	return daBatch, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
func (d *DACodecV0) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 89 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 89 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV0 {
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV0)
	}

	b := newDABatchV0(
		data[0],                              // version
		binary.BigEndian.Uint64(data[1:9]),   // batchIndex
		binary.BigEndian.Uint64(data[9:17]),  // l1MessagePopped
		binary.BigEndian.Uint64(data[17:25]), // totalL1MessagePopped
		common.BytesToHash(data[25:57]),      // dataHash
		common.BytesToHash(data[57:89]),      // parentBatchHash
		data[89:],                            // skippedL1MessageBitmap
	)

	return b, nil
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
func (d *DACodecV0) EstimateBlockL1CommitCalldataSize(b *Block) (uint64, error) {
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
	size += blockContextByteSize
	return size, nil
}

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func (d *DACodecV0) EstimateBlockL1CommitGas(b *Block) (uint64, error) {
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
		total += calldataNonZeroByteGas * txPayloadLength // an over-estimate: treat each byte as non-zero
		total += calldataNonZeroByteGas * 4               // 4 bytes payload length
		total += getKeccak256Gas(txPayloadLength)         // l2 tx hash
	}

	total += calldataNonZeroByteGas * blockContextByteSize

	// sload
	total += 2100 * numL1Messages // numL1Messages times cold sload in L1MessageQueue

	// staticcall
	total += 100 * numL1Messages // numL1Messages times call to L1MessageQueue
	total += 100 * numL1Messages // numL1Messages times warm address access to L1MessageQueue

	total += getMemoryExpansionCost(36) * numL1Messages // staticcall to proxy
	total += 100 * numL1Messages                        // read admin in proxy
	total += 100 * numL1Messages                        // read impl in proxy
	total += 100 * numL1Messages                        // access impl
	total += getMemoryExpansionCost(36) * numL1Messages // delegatecall to impl

	return total, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (d *DACodecV0) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	var totalL1CommitCalldataSize uint64
	for _, block := range c.Blocks {
		blockL1CommitCalldataSize, err := d.EstimateBlockL1CommitCalldataSize(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += blockL1CommitCalldataSize
	}
	return totalL1CommitCalldataSize, nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (d *DACodecV0) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	var totalTxNum uint64
	var totalL1CommitGas uint64
	for _, block := range c.Blocks {
		totalTxNum += uint64(len(block.Transactions))
		blockL1CommitGas, err := d.EstimateBlockL1CommitGas(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += blockL1CommitGas
	}

	numBlocks := uint64(len(c.Blocks))
	totalL1CommitGas += 100 * numBlocks                                           // numBlocks times warm sload
	totalL1CommitGas += calldataNonZeroByteGas                                    // numBlocks field of chunk encoding in calldata
	totalL1CommitGas += calldataNonZeroByteGas * numBlocks * blockContextByteSize // numBlocks of BlockContext in chunk

	totalL1CommitGas += getKeccak256Gas(58*numBlocks + 32*totalTxNum) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (d *DACodecV0) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	var totalL1CommitGas uint64

	// Add extra gas costs
	totalL1CommitGas += 100000                 // constant to account for ops like _getAdmin, _implementation, _requireNotPaused, etc
	totalL1CommitGas += 4 * 2100               // 4 one-time cold sload for commitBatch
	totalL1CommitGas += 20000                  // 1 time sstore
	totalL1CommitGas += 21000                  // base fee for tx
	totalL1CommitGas += calldataNonZeroByteGas // version in calldata

	// adjusting gas:
	// add 1 time cold sload (2100 gas) for L1MessageQueue
	// add 1 time cold address access (2600 gas) for L1MessageQueue
	// minus 1 time warm sload (100 gas) & 1 time warm address access (100 gas)
	totalL1CommitGas += (2100 + 2600 - 100 - 100)
	totalL1CommitGas += getKeccak256Gas(89 + 32)           // parent batch header hash, length is estimated as 89 (constant part)+ 32 (1 skippedL1MessageBitmap)
	totalL1CommitGas += calldataNonZeroByteGas * (89 + 32) // parent batch header in calldata

	// adjust batch data hash gas cost
	totalL1CommitGas += getKeccak256Gas(uint64(32 * len(b.Chunks)))

	totalL1MessagePoppedBefore := b.TotalL1MessagePoppedBefore

	for _, chunk := range b.Chunks {
		chunkL1CommitGas, err := d.EstimateChunkL1CommitGas(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += chunkL1CommitGas

		totalL1MessagePoppedInChunk := chunk.NumL1Messages(totalL1MessagePoppedBefore)
		totalL1MessagePoppedBefore += totalL1MessagePoppedInChunk

		totalL1CommitGas += calldataNonZeroByteGas * (32 * (totalL1MessagePoppedInChunk + 255) / 256)
		totalL1CommitGas += getKeccak256Gas(89 + 32*(totalL1MessagePoppedInChunk+255)/256)

		chunkL1CommitCalldataSize, err := d.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += getMemoryExpansionCost(chunkL1CommitCalldataSize)
	}

	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (d *DACodecV0) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	var totalL1CommitCalldataSize uint64
	for _, chunk := range b.Chunks {
		chunkL1CommitCalldataSize, err := d.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += chunkL1CommitCalldataSize
	}
	return totalL1CommitCalldataSize, nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func (d *DACodecV0) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (d *DACodecV0) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	return true, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (d *DACodecV0) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	return 0, 0, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (d *DACodecV0) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	return 0, 0, nil
}

// JSONFromBytes for CodecV0 returns empty values.
func (c *DACodecV0) JSONFromBytes(data []byte) ([]byte, error) {
	// DACodecV0 doesn't need this, so just return empty values
	return nil, nil
}
