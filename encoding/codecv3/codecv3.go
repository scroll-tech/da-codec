package codecv3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv1"
	"github.com/scroll-tech/da-codec/encoding/codecv2"
)

// DABlock represents a Data Availability Block.
type DABlock = codecv2.DABlock

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk = codecv2.DAChunk

// DABatch contains metadata about a batch of DAChunks.
type DABatch struct {
	// header
	Version                uint8
	BatchIndex             uint64
	L1MessagePopped        uint64
	TotalL1MessagePopped   uint64
	DataHash               common.Hash
	BlobVersionedHash      common.Hash
	ParentBatchHash        common.Hash
	LastBlockTimestamp     uint64
	BlobDataProof          [64]byte
	SkippedL1MessageBitmap []byte

	// blob payload
	blob *kzg4844.Blob
	z    *kzg4844.Point
}

// NewDABlock creates a new DABlock from the given encoding.Block and the total number of L1 messages popped before.
func NewDABlock(block *encoding.Block, totalL1MessagePoppedBefore uint64) (*DABlock, error) {
	return codecv2.NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given encoding.Chunk and the total number of L1 messages popped before.
func NewDAChunk(chunk *encoding.Chunk, totalL1MessagePoppedBefore uint64) (*DAChunk, error) {
	return codecv2.NewDAChunk(chunk, totalL1MessagePoppedBefore)
}

// NewDABatch creates a DABatch from the provided encoding.Batch.
func NewDABatch(batch *encoding.Batch) (*DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > codecv2.MaxNumChunks {
		return nil, fmt.Errorf("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, fmt.Errorf("too few chunks in batch")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, fmt.Errorf("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := codecv1.ComputeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := encoding.ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, err := codecv2.ConstructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	daBatch := DABatch{
		Version:                uint8(encoding.CodecV3),
		BatchIndex:             batch.Index,
		L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
		TotalL1MessagePopped:   totalL1MessagePoppedAfter,
		DataHash:               dataHash,
		BlobVersionedHash:      blobVersionedHash,
		ParentBatchHash:        batch.ParentBatchHash,
		LastBlockTimestamp:     batch.Chunks[len(batch.Chunks)-1].Blocks[len(batch.Chunks[len(batch.Chunks)-1].Blocks)-1].Header.Time,
		SkippedL1MessageBitmap: bitmapBytes,
		blob:                   blob,
		z:                      z,
	}

	daBatch.BlobDataProof, err = daBatch.BlobDataProofForBatchHeader()
	if err != nil {
		return nil, err
	}

	return &daBatch, nil
}

// NewDABatchFromBytes attempts to decode the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func NewDABatchFromBytes(data []byte) (*DABatch, error) {
	if len(data) < 193 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 193 bytes but got %d", len(data))
	}

	b := &DABatch{
		Version:                data[0],
		BatchIndex:             binary.BigEndian.Uint64(data[1:9]),
		L1MessagePopped:        binary.BigEndian.Uint64(data[9:17]),
		TotalL1MessagePopped:   binary.BigEndian.Uint64(data[17:25]),
		DataHash:               common.BytesToHash(data[25:57]),
		BlobVersionedHash:      common.BytesToHash(data[57:89]),
		ParentBatchHash:        common.BytesToHash(data[89:121]),
		LastBlockTimestamp:     binary.BigEndian.Uint64(data[121:129]),
		BlobDataProof:          [64]byte(data[129:193]),
		SkippedL1MessageBitmap: data[193:],
	}

	return b, nil
}

// Encode serializes the DABatch into bytes.
func (b *DABatch) Encode() []byte {
	batchBytes := make([]byte, 193+len(b.SkippedL1MessageBitmap))
	batchBytes[0] = b.Version
	binary.BigEndian.PutUint64(batchBytes[1:9], b.BatchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:17], b.L1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:25], b.TotalL1MessagePopped)
	copy(batchBytes[25:57], b.DataHash[:])
	copy(batchBytes[57:89], b.BlobVersionedHash[:])
	copy(batchBytes[89:121], b.ParentBatchHash[:])
	binary.BigEndian.PutUint64(batchBytes[121:129], b.LastBlockTimestamp)
	copy(batchBytes[129:193], b.BlobDataProof[:])
	copy(batchBytes[193:], b.SkippedL1MessageBitmap)
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *DABatch) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// BlobDataProofForBatchHeader computes the abi-encoded blob verification data.
func (b *DABatch) BlobDataProofForBatchHeader() ([64]byte, error) {
	if b.blob == nil {
		return [64]byte{}, errors.New("called BlobDataProofForBatchHeader with empty blob")
	}
	if b.z == nil {
		return [64]byte{}, errors.New("called BlobDataProofForBatchHeader with empty z")
	}

	_, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return [64]byte{}, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	// Memory layout of result:
	// | z       | y       |
	// |---------|---------|
	// | bytes32 | bytes32 |
	var result [64]byte
	copy(result[:32], b.z[:])
	copy(result[32:], y[:])

	return result, nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *DABatch) BlobDataProofForPointEvaluation() ([]byte, error) {
	if b.blob == nil {
		return nil, errors.New("called BlobDataProofForPointEvaluation with empty blob")
	}
	if b.z == nil {
		return nil, errors.New("called BlobDataProofForPointEvaluation with empty z")
	}

	commitment, err := kzg4844.BlobToCommitment(b.blob)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob commitment")
	}

	proof, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return nil, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	// Memory layout of ``_blobDataProof``:
	// | z       | y       | kzg_commitment | kzg_proof |
	// |---------|---------|----------------|-----------|
	// | bytes32 | bytes32 | bytes48        | bytes48   |

	values := []interface{}{*b.z, y, commitment, proof}
	blobDataProofArgs, err := codecv1.GetBlobDataProofArgs()
	if err != nil {
		return nil, fmt.Errorf("failed to get blob data proof args, err: %w", err)
	}
	return blobDataProofArgs.Pack(values...)
}

// Blob returns the blob of the batch.
func (b *DABatch) Blob() *kzg4844.Blob {
	return b.blob
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func EstimateChunkL1CommitBatchSizeAndBlobSize(c *encoding.Chunk) (uint64, uint64, error) {
	return codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(c)
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func EstimateBatchL1CommitBatchSizeAndBlobSize(b *encoding.Batch) (uint64, uint64, error) {
	return codecv2.EstimateBatchL1CommitBatchSizeAndBlobSize(b)
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func EstimateChunkL1CommitCalldataSize(c *encoding.Chunk) uint64 {
	return codecv2.EstimateChunkL1CommitCalldataSize(c)
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func EstimateBatchL1CommitCalldataSize(b *encoding.Batch) uint64 {
	return codecv2.EstimateBatchL1CommitCalldataSize(b)
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func EstimateChunkL1CommitGas(c *encoding.Chunk) uint64 {
	return codecv2.EstimateChunkL1CommitGas(c) + 50000 // plus 50000 for the point-evaluation precompile call.
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func EstimateBatchL1CommitGas(b *encoding.Batch) uint64 {
	return codecv2.EstimateBatchL1CommitGas(b) + 50000 // plus 50000 for the point-evaluation precompile call.
}
