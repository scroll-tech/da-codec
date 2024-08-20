package encoding

import (
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// DABlock represents a Data Availability Block.
type DABlock interface {
	Encode() []byte
	Decode([]byte) error
}

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk interface {
	Encode() []byte
	Hash() (common.Hash, error)
}

// DABatch contains metadata about a batch of DAChunks.
type DABatch interface {
	Encode() []byte
	Hash() common.Hash
	BlobDataProofForPointEvaluation() ([]byte, error)
	Blob() *kzg4844.Blob
	BlobBytes() []byte
}

// Codec represents the interface for encoding and decoding DA-related structures.
type Codec interface {
	NewDABlock(*Block, uint64) (DABlock, error)
	NewDAChunk(*Chunk, uint64) (DAChunk, error)
	NewDABatch(*Batch) (DABatch, error)
	NewDABatchFromBytes([]byte) (DABatch, error)

	ComputeBatchDataHash([]*Chunk, uint64) (common.Hash, error)
	ConstructBlobPayload([]*Chunk, bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error)

	EstimateChunkL1CommitBatchSizeAndBlobSize(*Chunk) (uint64, uint64, error)
	EstimateBatchL1CommitBatchSizeAndBlobSize(*Batch) (uint64, uint64, error)
	CheckChunkCompressedDataCompatibility(*Chunk) (bool, error)
	CheckBatchCompressedDataCompatibility(*Batch) (bool, error)
	EstimateChunkL1CommitCalldataSize(*Chunk) uint64
	EstimateChunkL1CommitGas(*Chunk) uint64
	EstimateBatchL1CommitGas(*Batch) uint64
	EstimateBatchL1CommitCalldataSize(*Batch) uint64

	SetCompression(enable bool) // only used for codecv4
}
