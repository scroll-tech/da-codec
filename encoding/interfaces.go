package encoding

import (
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk interface {
	Encode() ([]byte, error)
	Hash() (common.Hash, error)
}

// DABatch contains metadata about a batch of DAChunks.
type DABatch interface {
	Encode() []byte
	Hash() common.Hash
	BlobDataProofForPointEvaluation() ([]byte, error)
	Blob() *kzg4844.Blob
	BlobBytes() []byte
	BlobVersionedHashes() []common.Hash
}

// Codec represents the interface for encoding and decoding DA-related structures.
type Codec interface {
	NewDABlock(*Block, uint64) (*DABlock, error)
	NewDAChunk(*Chunk, uint64) (DAChunk, error)
	NewDABatch(*Batch) (DABatch, error)
	NewDABatchFromBytes([]byte) (DABatch, error)

	EstimateChunkL1CommitBatchSizeAndBlobSize(*Chunk) (uint64, uint64, error)
	EstimateBatchL1CommitBatchSizeAndBlobSize(*Batch) (uint64, uint64, error)
	CheckChunkCompressedDataCompatibility(*Chunk) (bool, error)
	CheckBatchCompressedDataCompatibility(*Batch) (bool, error)
	EstimateChunkL1CommitCalldataSize(*Chunk) (uint64, error)
	EstimateChunkL1CommitGas(*Chunk) (uint64, error)
	EstimateBatchL1CommitGas(*Batch) (uint64, error)
	EstimateBatchL1CommitCalldataSize(*Batch) (uint64, error)

	SetCompression(enable bool) // only used for codecv4
}

// CodecVersion represents the version of the codec.
type CodecVersion int

const (
	CodecV0 CodecVersion = iota
	CodecV1
	CodecV2
	CodecV3
	CodecV4
)

// GetCodec returns the appropriate codec for the given version.
func GetCodec(version CodecVersion) (Codec, error) {
	switch version {
	case CodecV0:
		return &DACodecV0{}, nil
	case CodecV1:
		return &DACodecV1{}, nil
	case CodecV2:
		return &DACodecV2{}, nil
	case CodecV3:
		return &DACodecV3{}, nil
	case CodecV4:
		return &DACodecV4{}, nil
	default:
		return nil, fmt.Errorf("unsupported codec version: %d", version)
	}
}