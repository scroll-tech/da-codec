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
func (d *DACodecV0) MaxNumChunksPerBatch() int {
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
	if chunk == nil {
		return nil, errors.New("chunk is nil")
	}

	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > math.MaxUint8 {
		return nil, fmt.Errorf("number of blocks (%d) exceeds maximum allowed (%d)", len(chunk.Blocks), math.MaxUint8)
	}

	blocks := make([]DABlock, 0, len(chunk.Blocks))
	txs := make([][]*types.TransactionData, 0, len(chunk.Blocks))

	for _, block := range chunk.Blocks {
		b, err := d.NewDABlock(block, totalL1MessagePoppedBefore)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
		totalL1MessagePoppedBefore += block.NumL1Messages(totalL1MessagePoppedBefore)
		txs = append(txs, block.Transactions)
	}

	if len(blocks) != len(txs) {
		return nil, fmt.Errorf("number of blocks (%d) does not match number of transactions (%d)", len(blocks), len(txs))
	}

	return &daChunkV0{
		blocks:       blocks,
		transactions: txs,
	}, nil
}

// DecodeDAChunksRawTx takes a byte slice and decodes it into a []*DAChunkRawTx.
func (d *DACodecV0) DecodeDAChunksRawTx(chunkBytes [][]byte) ([]*DAChunkRawTx, error) {
	chunks := make([]*DAChunkRawTx, 0, len(chunkBytes))
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
			txNum := int(block.NumTransactions()) - int(block.NumL1Messages())
			if txNum < 0 {
				return nil, fmt.Errorf("invalid transaction count: NumL1Messages (%d) exceeds NumTransactions (%d)", block.NumL1Messages(), block.NumTransactions())
			}
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

func (d *DACodecV0) DecodeBlob(blob *kzg4844.Blob) (DABlobPayload, error) {
	return nil, nil
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV0) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > d.MaxNumChunksPerBatch() {
		return nil, fmt.Errorf("too many chunks in batch: got %d, maximum allowed is %d", len(batch.Chunks), d.MaxNumChunksPerBatch())
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("batch must contain at least one chunk")
	}

	// compute batch data hash
	dataHash, err := d.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, fmt.Errorf("failed to compute batch data hash, index: %d, err: %w", batch.Index, err)
	}

	// skipped L1 messages bitmap
	skippedL1MessageBitmap, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, fmt.Errorf("failed to construct skipped bitmap, index: %d, err: %w", batch.Index, err)
	}

	if totalL1MessagePoppedAfter < batch.TotalL1MessagePoppedBefore {
		return nil, fmt.Errorf("batch index: %d, totalL1MessagePoppedAfter (%d) is less than batch.TotalL1MessagePoppedBefore (%d)", batch.Index, totalL1MessagePoppedAfter, batch.TotalL1MessagePoppedBefore)
	}
	l1MessagePopped := totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore

	daBatch := newDABatchV0(
		CodecV0,                   // version
		batch.Index,               // batchIndex
		l1MessagePopped,           // l1MessagePopped
		totalL1MessagePoppedAfter, // totalL1MessagePopped
		dataHash,                  // dataHash
		batch.ParentBatchHash,     // parentBatchHash
		skippedL1MessageBitmap,    // skippedL1MessageBitmap
	)

	return daBatch, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
func (d *DACodecV0) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < daBatchV0EncodedMinLength {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least %d bytes but got %d", daBatchV0EncodedMinLength, len(data))
	}

	if CodecVersion(data[daBatchOffsetVersion]) != CodecV0 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV0, data[daBatchOffsetVersion])
	}

	return newDABatchV0(
		CodecVersion(data[daBatchOffsetVersion]),                                                          // version
		binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV0OffsetL1MessagePopped]),             // batchIndex
		binary.BigEndian.Uint64(data[daBatchV0OffsetL1MessagePopped:daBatchV0OffsetTotalL1MessagePopped]), // l1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV0OffsetTotalL1MessagePopped:daBatchOffsetDataHash]),          // totalL1MessagePopped
		common.BytesToHash(data[daBatchOffsetDataHash:daBatchV0OffsetParentBatchHash]),                    // dataHash
		common.BytesToHash(data[daBatchV0OffsetParentBatchHash:daBatchV0OffsetSkippedL1MessageBitmap]),    // parentBatchHash
		data[daBatchV0OffsetSkippedL1MessageBitmap:],                                                      // skippedL1MessageBitmap
	), nil
}

func (d *DACodecV0) NewDABatchFromParams(_ uint64, _, _ common.Hash) (DABatch, error) {
	return nil, nil
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
func (d *DACodecV0) EstimateBlockL1CommitCalldataSize(b *Block) (uint64, error) {
	var size uint64
	for _, txData := range b.Transactions {
		if txData.Type == types.L1MessageTxType {
			continue
		}
		size += payloadLengthBytes
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
	total += coldSloadGas * numL1Messages // numL1Messages times cold sload in L1MessageQueue

	// staticcall
	total += warmAddressAccessGas * numL1Messages // numL1Messages times call to L1MessageQueue
	total += warmAddressAccessGas * numL1Messages // numL1Messages times warm address access to L1MessageQueue

	total += getMemoryExpansionCost(functionSignatureBytes+defaultParameterBytes) * numL1Messages // staticcall to proxy
	total += warmAddressAccessGas * numL1Messages                                                 // read admin in proxy
	total += warmAddressAccessGas * numL1Messages                                                 // read impl in proxy
	total += warmAddressAccessGas * numL1Messages                                                 // access impl
	total += getMemoryExpansionCost(functionSignatureBytes+defaultParameterBytes) * numL1Messages // delegatecall to impl

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
	totalL1CommitGas += warmSloadGas * numBlocks // numBlocks times warm sload
	totalL1CommitGas += calldataNonZeroByteGas   // numBlocks field of chunk encoding in calldata

	totalL1CommitGas += getKeccak256Gas(blockContextBytesForHashing*numBlocks + common.HashLength*totalTxNum) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (d *DACodecV0) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	var totalL1CommitGas uint64

	// Add extra gas costs
	totalL1CommitGas += extraGasCost           // constant to account for ops like _getAdmin, _implementation, _requireNotPaused, etc
	totalL1CommitGas += 4 * coldSloadGas       // 4 one-time cold sload for commitBatch
	totalL1CommitGas += sstoreGas              // 1 time sstore
	totalL1CommitGas += baseTxGas              // base gas for tx
	totalL1CommitGas += calldataNonZeroByteGas // version in calldata

	// adjusting gas:
	// add 1 time cold sload (2100 gas) for L1MessageQueue
	// add 1 time cold address access (2600 gas) for L1MessageQueue
	// minus 1 time warm sload (100 gas) & 1 time warm address access (100 gas)
	totalL1CommitGas += (coldSloadGas + coldAddressAccessGas - warmSloadGas - warmAddressAccessGas)
	totalL1CommitGas += getKeccak256Gas(daBatchV0EncodedMinLength + skippedL1MessageBitmapByteSize)           // parent batch header hash, length is estimated as (constant part) + (1 skippedL1MessageBitmap)
	totalL1CommitGas += calldataNonZeroByteGas * (daBatchV0EncodedMinLength + skippedL1MessageBitmapByteSize) // parent batch header in calldata

	// adjust batch data hash gas cost
	totalL1CommitGas += getKeccak256Gas(uint64(common.HashLength * len(b.Chunks)))

	totalL1MessagePoppedBefore := b.TotalL1MessagePoppedBefore

	for _, chunk := range b.Chunks {
		chunkL1CommitGas, err := d.EstimateChunkL1CommitGas(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += chunkL1CommitGas

		totalL1MessagePoppedInChunk := chunk.NumL1Messages(totalL1MessagePoppedBefore)
		totalL1MessagePoppedBefore += totalL1MessagePoppedInChunk

		totalL1CommitGas += calldataNonZeroByteGas * (skippedL1MessageBitmapByteSize * (totalL1MessagePoppedInChunk + 255) / 256)
		totalL1CommitGas += getKeccak256Gas(daBatchV0EncodedMinLength + skippedL1MessageBitmapByteSize*(totalL1MessagePoppedInChunk+255)/256)

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

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a single chunk.
func (d *DACodecV0) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	return 0, 0, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV0) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	return 0, 0, nil
}

// JSONFromBytes for CodecV0 returns empty values.
func (c *DACodecV0) JSONFromBytes(data []byte) ([]byte, error) {
	// DACodecV0 doesn't need this, so just return empty values
	return nil, nil
}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a batch in the contracts,
// the latter is used in the public input to the provers.
func (d *DACodecV0) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	dataBytes := make([]byte, 0, len(chunks)*common.HashLength)
	totalL1MessagePoppedBeforeChunk := totalL1MessagePoppedBefore

	for _, chunk := range chunks {
		daChunk, err := d.NewDAChunk(chunk, totalL1MessagePoppedBeforeChunk)
		if err != nil {
			return common.Hash{}, err
		}
		totalL1MessagePoppedBeforeChunk += chunk.NumL1Messages(totalL1MessagePoppedBeforeChunk)
		chunkHash, err := daChunk.Hash()
		if err != nil {
			return common.Hash{}, err
		}
		dataBytes = append(dataBytes, chunkHash.Bytes()...)
	}

	dataHash := crypto.Keccak256Hash(dataBytes)
	return dataHash, nil
}
