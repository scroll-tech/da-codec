package encoding

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
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
	skippedL1MessageBitmap, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, challengeDigest, err := d.constructBlobPayload(batch.Chunks, d.MaxNumChunksPerBatch())
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
		CodecV3,                   // version
		batch.Index,               // batchIndex
		l1MessagePopped,           // l1MessagePopped
		totalL1MessagePoppedAfter, // totalL1MessagePopped
		lastBlock.Header.Time,     // lastBlockTimestamp
		dataHash,                  // dataHash
		batch.ParentBatchHash,     // parentBatchHash
		blobVersionedHash,         // blobVersionedHash
		skippedL1MessageBitmap,    // skippedL1MessageBitmap
		blob,                      // blob
		z,                         // z
		blobBytes,                 // blobBytes
		challengeDigest,           // challengeDigest
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
		CodecVersion(data[daBatchOffsetVersion]),                                                          // version
		binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV3OffsetL1MessagePopped]),             // batchIndex
		binary.BigEndian.Uint64(data[daBatchV3OffsetL1MessagePopped:daBatchV3OffsetTotalL1MessagePopped]), // l1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV3OffsetTotalL1MessagePopped:daBatchOffsetDataHash]),          // totalL1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV3OffsetLastBlockTimestamp:daBatchV3OffsetBlobDataProof]),     // lastBlockTimestamp
		common.BytesToHash(data[daBatchOffsetDataHash:daBatchV3OffsetBlobVersionedHash]),                  // dataHash
		common.BytesToHash(data[daBatchV3OffsetParentBatchHash:daBatchV3OffsetLastBlockTimestamp]),        // parentBatchHash
		common.BytesToHash(data[daBatchV3OffsetBlobVersionedHash:daBatchV3OffsetParentBatchHash]),         // blobVersionedHash
		nil,           // skippedL1MessageBitmap
		nil,           // blob
		nil,           // z
		nil,           // blobBytes
		common.Hash{}, // challengeDigest
		[2]common.Hash{ // blobDataProof
			common.BytesToHash(data[daBatchV3OffsetBlobDataProof : daBatchV3OffsetBlobDataProof+kzgPointByteSize]),
			common.BytesToHash(data[daBatchV3OffsetBlobDataProof+kzgPointByteSize : daBatchV3EncodedLength]),
		},
	), nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (d *DACodecV3) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	// Reuse the V2 implementation, should have slightly different gas cost, but sufficient for estimation in practice,
	// since we have extraGasCost to over-estimate the gas cost.
	totalL1CommitGas, err := d.DACodecV2.EstimateChunkL1CommitGas(c)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate L1 commit gas for chunk: %w", err)
	}
	totalL1CommitGas += blobTxPointEvaluationPrecompileGas // plus gas cost for the point-evaluation precompile call.
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (d *DACodecV3) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	// Reuse the V2 implementation, should have slightly different gas cost, but sufficient for estimation in practice,
	// since we have extraGasCost to over-estimate the gas cost.
	totalL1CommitGas, err := d.DACodecV2.EstimateBatchL1CommitGas(b)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate L1 commit gas for batch: %w", err)
	}
	totalL1CommitGas += blobTxPointEvaluationPrecompileGas // plus gas cost for the point-evaluation precompile call.
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
		return nil, fmt.Errorf("failed to marshal DABatch to JSON, version %d, hash %s: %w", batch.Version(), batch.Hash(), err)
	}

	return jsonBytes, nil
}
