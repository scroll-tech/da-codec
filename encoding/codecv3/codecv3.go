package codecv3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/accounts/abi"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv2"
)

// MaxNumChunks is the maximum number of chunks that a batch can contain.
const MaxNumChunks = codecv2.MaxNumChunks

// DABlock represents a Data Availability Block.
type DABlock = codecv2.DABlock

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk = codecv2.DAChunk

// DABatch contains metadata about a batch of DAChunks.
type DABatch struct {
	// header
	Version              uint8          `json:"version"`
	BatchIndex           uint64         `json:"batch_index"`
	L1MessagePopped      uint64         `json:"l1_message_popped"`
	TotalL1MessagePopped uint64         `json:"total_l1_message_popped"`
	DataHash             common.Hash    `json:"data_hash"`
	BlobVersionedHash    common.Hash    `json:"blob_versioned_hash"`
	ParentBatchHash      common.Hash    `json:"parent_batch_hash"`
	LastBlockTimestamp   uint64         `json:"last_block_timestamp"`
	BlobDataProof        [2]common.Hash `json:"blob_data_proof"`

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
	if len(batch.Chunks) > MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, errors.New("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := ComputeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	_, totalL1MessagePoppedAfter, err := encoding.ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, err := ConstructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	daBatch := DABatch{
		Version:              uint8(encoding.CodecV3),
		BatchIndex:           batch.Index,
		L1MessagePopped:      totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
		TotalL1MessagePopped: totalL1MessagePoppedAfter,
		DataHash:             dataHash,
		BlobVersionedHash:    blobVersionedHash,
		ParentBatchHash:      batch.ParentBatchHash,
		LastBlockTimestamp:   lastBlock.Header.Time,
		blob:                 blob,
		z:                    z,
	}

	daBatch.BlobDataProof, err = daBatch.blobDataProofForPICircuit()
	if err != nil {
		return nil, err
	}

	return &daBatch, nil
}

// ComputeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func ComputeBatchDataHash(chunks []*encoding.Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	return codecv2.ComputeBatchDataHash(chunks, totalL1MessagePoppedBefore)
}

// ConstructBlobPayload constructs the 4844 blob payload.
func ConstructBlobPayload(chunks []*encoding.Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, error) {
	return codecv2.ConstructBlobPayload(chunks, useMockTxData)
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func NewDABatchFromBytes(data []byte) (*DABatch, error) {
	if len(data) != 193 {
		return nil, fmt.Errorf("invalid data length for DABatch, expected 193 bytes but got %d", len(data))
	}

	b := &DABatch{
		Version:              data[0],
		BatchIndex:           binary.BigEndian.Uint64(data[1:9]),
		L1MessagePopped:      binary.BigEndian.Uint64(data[9:17]),
		TotalL1MessagePopped: binary.BigEndian.Uint64(data[17:25]),
		DataHash:             common.BytesToHash(data[25:57]),
		BlobVersionedHash:    common.BytesToHash(data[57:89]),
		ParentBatchHash:      common.BytesToHash(data[89:121]),
		LastBlockTimestamp:   binary.BigEndian.Uint64(data[121:129]),
		BlobDataProof: [2]common.Hash{
			common.BytesToHash(data[129:161]),
			common.BytesToHash(data[161:193]),
		},
	}

	return b, nil
}

// Encode serializes the DABatch into bytes.
func (b *DABatch) Encode() []byte {
	batchBytes := make([]byte, 193)
	batchBytes[0] = b.Version
	binary.BigEndian.PutUint64(batchBytes[1:9], b.BatchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:17], b.L1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:25], b.TotalL1MessagePopped)
	copy(batchBytes[25:57], b.DataHash[:])
	copy(batchBytes[57:89], b.BlobVersionedHash[:])
	copy(batchBytes[89:121], b.ParentBatchHash[:])
	binary.BigEndian.PutUint64(batchBytes[121:129], b.LastBlockTimestamp)
	copy(batchBytes[129:161], b.BlobDataProof[0].Bytes())
	copy(batchBytes[161:193], b.BlobDataProof[1].Bytes())
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *DABatch) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// blobDataProofForPICircuit computes the abi-encoded blob verification data.
func (b *DABatch) blobDataProofForPICircuit() ([2]common.Hash, error) {
	if b.blob == nil {
		return [2]common.Hash{}, errors.New("called blobDataProofForPICircuit with empty blob")
	}
	if b.z == nil {
		return [2]common.Hash{}, errors.New("called blobDataProofForPICircuit with empty z")
	}

	_, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return [2]common.Hash{}, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	// Memory layout of result:
	// | z       | y       |
	// |---------|---------|
	// | bytes32 | bytes32 |
	var result [2]common.Hash
	result[0] = common.BytesToHash(b.z[:])
	result[1] = common.BytesToHash(y[:])

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
		return nil, errors.New("failed to create blob commitment")
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
	blobDataProofArgs, err := GetBlobDataProofArgs()
	if err != nil {
		return nil, fmt.Errorf("failed to get blob data proof args, err: %w", err)
	}
	return blobDataProofArgs.Pack(values...)
}

// Blob returns the blob of the batch.
func (b *DABatch) Blob() *kzg4844.Blob {
	return b.blob
}

// ConvertBlobToBlobBytes converts the canonical blob representation into DA blob bytes.
func (b *DABatch) ConvertBlobToBlobBytes() ([]byte, error) {
	var blobBytes [126976]byte

	for from := 0; from < len(b.blob); from += 32 {
		copy(blobBytes[from/32*31:], b.blob[from+1:from+32])
	}

	metadataLength := 2 + MaxNumChunks*4
	numChunks := binary.BigEndian.Uint16(blobBytes[:2])

	if numChunks > MaxNumChunks {
		return nil, fmt.Errorf("number of chunks (%d) exceeds maximum allowed chunks (%d)", numChunks, MaxNumChunks)
	}

	totalSize := metadataLength
	for i := 0; i < int(numChunks); i++ {
		chunkSize := binary.BigEndian.Uint32(blobBytes[2+4*i:])
		totalSize += int(chunkSize)

		if totalSize > len(blobBytes) {
			return nil, fmt.Errorf("calculated total size (%d) exceeds the length of blobBytes (%d)", totalSize, len(blobBytes))
		}
	}

	return blobBytes[:totalSize], nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func EstimateChunkL1CommitBatchSizeAndBlobSize(c *encoding.Chunk) (uint64, uint64, error) {
	return codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(c)
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func EstimateBatchL1CommitBatchSizeAndBlobSize(b *encoding.Batch) (uint64, uint64, error) {
	return codecv2.EstimateBatchL1CommitBatchSizeAndBlobSize(b)
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func CheckChunkCompressedDataCompatibility(c *encoding.Chunk) (bool, error) {
	return codecv2.CheckChunkCompressedDataCompatibility(c)
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func CheckBatchCompressedDataCompatibility(b *encoding.Batch) (bool, error) {
	return codecv2.CheckBatchCompressedDataCompatibility(b)
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

// GetBlobDataProofArgs gets the blob data proof arguments for batch commitment and returns error if initialization fails.
func GetBlobDataProofArgs() (*abi.Arguments, error) {
	return codecv2.GetBlobDataProofArgs()
}
