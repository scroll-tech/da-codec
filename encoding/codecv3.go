package encoding

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/params"
)

type DACodecV3 struct {
	DACodecV2
}

// Version returns the codec version.
func (d *DACodecV3) Version() CodecVersion {
	return CodecV3
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV3) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > d.MaxNumChunksPerBatch() {
		return nil, fmt.Errorf("too many chunks in batch: got %d, maximum allowed is %d", len(batch.Chunks), d.MaxNumChunksPerBatch())
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("batch must contain at least one chunk")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, errors.New("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := d.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := d.constructBlobPayload(batch.Chunks, d.MaxNumChunksPerBatch(), false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	if totalL1MessagePoppedAfter < batch.TotalL1MessagePoppedBefore {
		return nil, fmt.Errorf("batch index: %d, totalL1MessagePoppedAfter (%d) is less than batch.TotalL1MessagePoppedBefore (%d)", batch.Index, totalL1MessagePoppedAfter, batch.TotalL1MessagePoppedBefore)
	}
	l1MessagePopped := totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore

	return newDABatchV3(
		uint8(CodecV3),            // version
		batch.Index,               // batchIndex
		l1MessagePopped,           // l1MessagePopped
		totalL1MessagePoppedAfter, // totalL1MessagePopped
		lastBlock.Header.Time,     // lastBlockTimestamp
		dataHash,                  // dataHash
		batch.ParentBatchHash,     // parentBatchHash
		blobVersionedHash,         // blobVersionedHash
		bitmapBytes,               // skippedL1MessageBitmap
		blob,                      // blob
		z,                         // z
		blobBytes,                 // blobBytes
	)
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields and skipped L1 message bitmap empty.
func (d *DACodecV3) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) != daBatchV3EncodedLength {
		return nil, fmt.Errorf("invalid data length for DABatch, expected %d bytes but got %d", daBatchV3EncodedLength, len(data))
	}

	if CodecVersion(data[daBatchOffsetVersion]) != CodecV3 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV3, data[daBatchOffsetVersion])
	}

	return newDABatchV3WithProof(
		data[daBatchOffsetVersion], // version
		binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV3OffsetL1MessagePopped]),             // batchIndex
		binary.BigEndian.Uint64(data[daBatchV3OffsetL1MessagePopped:daBatchV3OffsetTotalL1MessagePopped]), // l1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV3OffsetTotalL1MessagePopped:daBatchOffsetDataHash]),          // totalL1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV3OffsetLastBlockTimestamp:daBatchV3OffsetBlobDataProof]),     // lastBlockTimestamp
		common.BytesToHash(data[daBatchOffsetDataHash:daBatchV3OffsetBlobVersionedHash]),                  // dataHash
		common.BytesToHash(data[daBatchV3OffsetParentBatchHash:daBatchV3OffsetLastBlockTimestamp]),        // parentBatchHash
		common.BytesToHash(data[daBatchV3OffsetBlobVersionedHash:daBatchV3OffsetParentBatchHash]),         // blobVersionedHash
		nil, // skippedL1MessageBitmap
		nil, // blob
		nil, // z
		nil, // blobBytes
		[2]common.Hash{ // blobDataProof
			common.BytesToHash(data[daBatchV3OffsetBlobDataProof : daBatchV3OffsetBlobDataProof+kzgPointLength]),
			common.BytesToHash(data[daBatchV3OffsetBlobDataProof+kzgPointLength : daBatchV3EncodedLength]),
		},
	), nil
}

// estimateChunkL1CommitGasWithoutPointEvaluation calculates the total L1 commit gas without point-evaluation for this chunk approximately.
func (d *DACodecV3) estimateChunkL1CommitGasWithoutPointEvaluation(c *Chunk) (uint64, error) {
	var totalNonSkippedL1Messages uint64
	var totalL1CommitGas uint64
	for _, block := range c.Blocks {
		transactions := uint64(len(block.Transactions))
		l2Transactions := block.NumL2Transactions()
		if transactions < l2Transactions {
			return 0, fmt.Errorf("number of L2 transactions (%d) exceeds total transactions (%d)", l2Transactions, transactions)
		}
		totalNonSkippedL1Messages += transactions - l2Transactions
		blockL1CommitGas, err := d.EstimateBlockL1CommitGas(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += blockL1CommitGas
	}

	numBlocks := uint64(len(c.Blocks))
	totalL1CommitGas += 100 * numBlocks                                              // numBlocks times warm sload
	totalL1CommitGas += calldataNonZeroByteGas                                       // numBlocks field of chunk encoding in calldata
	totalL1CommitGas += getKeccak256Gas(58*numBlocks + 32*totalNonSkippedL1Messages) // chunk hash

	return totalL1CommitGas, nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (d *DACodecV3) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	totalL1CommitGas, err := d.estimateChunkL1CommitGasWithoutPointEvaluation(c)
	if err != nil {
		return 0, err
	}
	totalL1CommitGas += params.BlobTxPointEvaluationPrecompileGas // plus gas cost for the point-evaluation precompile call.
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (d *DACodecV3) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
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
		chunkL1CommitGas, err := d.estimateChunkL1CommitGasWithoutPointEvaluation(chunk)
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

	totalL1CommitGas += params.BlobTxPointEvaluationPrecompileGas // plus gas cost for the point-evaluation precompile call.
	return totalL1CommitGas, nil
}

// JSONFromBytes converts the bytes to a daBatchV3 and then marshals it to JSON.
func (d *DACodecV3) JSONFromBytes(data []byte) ([]byte, error) {
	batch, err := d.NewDABatchFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DABatch from bytes: %w", err)
	}

	jsonBytes, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DABatch to JSON: %w", err)
	}

	return jsonBytes, nil
}
