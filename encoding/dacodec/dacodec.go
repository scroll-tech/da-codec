package dacodec

import (
	"github.com/scroll-tech/da-codec/encoding"
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
	NewDABlock(*encoding.Block, uint64) (DABlock, error)
	NewDAChunk(*encoding.Chunk, uint64) (DAChunk, error)
	NewDABatch(*encoding.Batch) (DABatch, error)
	NewDABatchFromBytes([]byte) (DABatch, error)

	ComputeBatchDataHash([]*encoding.Chunk, uint64) (common.Hash, error)
	ConstructBlobPayload([]*encoding.Chunk, bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error)

	EstimateChunkL1CommitBatchSizeAndBlobSize(*encoding.Chunk) (uint64, uint64, error)
	EstimateBatchL1CommitBatchSizeAndBlobSize(*encoding.Batch) (uint64, uint64, error)
	CheckChunkCompressedDataCompatibility(*encoding.Chunk) (bool, error)
	CheckBatchCompressedDataCompatibility(*encoding.Batch) (bool, error)
	EstimateChunkL1CommitCalldataSize(*encoding.Chunk) uint64
	EstimateChunkL1CommitGas(*encoding.Chunk) uint64
	EstimateBatchL1CommitGas(*encoding.Batch) uint64
	EstimateBatchL1CommitCalldataSize(*encoding.Batch) uint64
}
