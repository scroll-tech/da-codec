package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

type DACodecV3 struct{}

// Codecv3MaxNumChunks is the maximum number of chunks that a batch can contain.
const Codecv3MaxNumChunks = 45

// Version returns the codec version.
func (o *DACodecV3) Version() CodecVersion {
	return CodecV3
}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (o *DACodecV3) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (DABlock, error) {
	return (&DACodecV2{}).NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (o *DACodecV3) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	return (&DACodecV2{}).NewDAChunk(chunk, totalL1MessagePoppedBefore)
}

// NewDABatch creates a DABatch from the provided Batch.
func (o *DACodecV3) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > Codecv3MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, errors.New("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := o.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := o.constructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	daBatch := DABatchV3{
		DABatchV0: DABatchV0{
			Version:                uint8(CodecV3),
			BatchIndex:             batch.Index,
			L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
			TotalL1MessagePopped:   totalL1MessagePoppedAfter,
			DataHash:               dataHash,
			ParentBatchHash:        batch.ParentBatchHash,
			SkippedL1MessageBitmap: bitmapBytes,
		},
		BlobVersionedHash:  blobVersionedHash,
		LastBlockTimestamp: lastBlock.Header.Time,
		blob:               blob,
		z:                  z,
		blobBytes:          blobBytes,
	}

	daBatch.BlobDataProof, err = daBatch.blobDataProofForPICircuit()
	if err != nil {
		return nil, err
	}

	return &daBatch, nil
}

// NewDABatchWithExpectedBlobVersionedHashes creates a DABatch from the provided Batch.
// It also checks if the blob versioned hashes are as expected.
func (o *DACodecV3) NewDABatchWithExpectedBlobVersionedHashes(batch *Batch, hashes []common.Hash) (DABatch, error) {
	daBatch, err := o.NewDABatch(batch)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(daBatch.BlobVersionedHashes(), hashes) {
		return nil, fmt.Errorf("blob versioned hashes do not match. Expected: %v, Got: %v", hashes, daBatch.BlobVersionedHashes())
	}

	return daBatch, nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (o *DACodecV3) constructBlobPayload(chunks []*Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	return (&DACodecV2{}).constructBlobPayload(chunks, useMockTxData)
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields and skipped L1 message bitmap empty.
func (o *DACodecV3) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) != 193 {
		return nil, fmt.Errorf("invalid data length for DABatch, expected 193 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV3 {
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV3)
	}

	b := &DABatchV3{
		DABatchV0: DABatchV0{
			Version:              data[0],
			BatchIndex:           binary.BigEndian.Uint64(data[1:9]),
			L1MessagePopped:      binary.BigEndian.Uint64(data[9:17]),
			TotalL1MessagePopped: binary.BigEndian.Uint64(data[17:25]),
			DataHash:             common.BytesToHash(data[25:57]),
			ParentBatchHash:      common.BytesToHash(data[89:121]),
		},
		BlobVersionedHash:  common.BytesToHash(data[57:89]),
		LastBlockTimestamp: binary.BigEndian.Uint64(data[121:129]),
		BlobDataProof: [2]common.Hash{
			common.BytesToHash(data[129:161]),
			common.BytesToHash(data[161:193]),
		},
	}

	return b, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (o *DACodecV3) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	return (&DACodecV2{}).EstimateChunkL1CommitBatchSizeAndBlobSize(c)
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (o *DACodecV3) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	return (&DACodecV2{}).EstimateBatchL1CommitBatchSizeAndBlobSize(b)
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func (o *DACodecV3) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	return (&DACodecV2{}).CheckChunkCompressedDataCompatibility(c)
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (o *DACodecV3) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	return (&DACodecV2{}).CheckBatchCompressedDataCompatibility(b)
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (o *DACodecV3) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return (&DACodecV2{}).EstimateChunkL1CommitCalldataSize(c)
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (o *DACodecV3) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	return (&DACodecV2{}).EstimateBatchL1CommitCalldataSize(b)
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (o *DACodecV3) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	chunkL1CommitGas, err := (&DACodecV2{}).EstimateChunkL1CommitGas(c)
	if err != nil {
		return 0, err
	}
	return chunkL1CommitGas + 50000, nil // plus 50000 for the point-evaluation precompile call.
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (o *DACodecV3) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	batchL1CommitGas, err := (&DACodecV2{}).EstimateBatchL1CommitGas(b)
	if err != nil {
		return 0, err
	}
	return batchL1CommitGas + 50000, nil // plus 50000 for the point-evaluation precompile call.
}

// SetCompression enables or disables compression.
func (o *DACodecV3) SetCompression(enable bool) {}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func (o *DACodecV3) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	return (&DACodecV2{}).computeBatchDataHash(chunks, totalL1MessagePoppedBefore)
}

// DecodeDAChunks takes a byte slice and decodes it into a []DAChunk
func (o *DACodecV3) DecodeDAChunks(bytes [][]byte) ([]DAChunk, error) {
	return (&DACodecV2{}).DecodeDAChunks(bytes)
}