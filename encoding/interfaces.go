package encoding

import (
	"fmt"
	"math/big"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/params"
)

// DABlock represents a Data Availability Block.
type DABlock interface {
	Encode() []byte
	Decode([]byte) error
	Number() uint64
	NumTransactions() uint16
	NumL1Messages() uint16
}

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk interface {
	Encode() ([]byte, error)
	Hash() (common.Hash, error)
	BlockRange() (uint64, uint64, error)
}

// DABatch contains metadata about a batch of DAChunks.
type DABatch interface {
	Encode() []byte
	Hash() common.Hash
	DataHash() common.Hash
	BlobDataProofForPointEvaluation() ([]byte, error)
	Blob() *kzg4844.Blob
	BlobBytes() []byte
	Version() CodecVersion
	SkippedL1MessageBitmap() []byte
}

// Codec represents the interface for encoding and decoding DA-related structures.
type Codec interface {
	Version() CodecVersion
	MaxNumChunksPerBatch() int

	NewDABlock(*Block, uint64) (DABlock, error)
	NewDAChunk(*Chunk, uint64) (DAChunk, error)
	NewDABatch(*Batch) (DABatch, error)
	NewDABatchFromBytes([]byte) (DABatch, error)

	DecodeDAChunksRawTx(chunkBytes [][]byte) ([]*DAChunkRawTx, error)
	DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error

	CheckChunkCompressedDataCompatibility(*Chunk) (bool, error)
	CheckBatchCompressedDataCompatibility(*Batch) (bool, error)

	EstimateChunkL1CommitBatchSizeAndBlobSize(*Chunk) (uint64, uint64, error)
	EstimateBatchL1CommitBatchSizeAndBlobSize(*Batch) (uint64, uint64, error)
	EstimateBlockL1CommitCalldataSize(*Block) (uint64, error)
	EstimateChunkL1CommitCalldataSize(*Chunk) (uint64, error)
	EstimateChunkL1CommitGas(*Chunk) (uint64, error)
	EstimateBatchL1CommitGas(*Batch) (uint64, error)
	EstimateBatchL1CommitCalldataSize(*Batch) (uint64, error)

	JSONFromBytes([]byte) ([]byte, error) // convert batch header bytes to JSON, this is only used to provide witness data for the prover.
}

// CodecVersion represents the version of the codec.
type CodecVersion uint8

const (
	CodecV0 CodecVersion = iota
	CodecV1
	CodecV2
	CodecV3
	CodecV4
)

// CodecFromVersion returns the appropriate codec for the given version.
func CodecFromVersion(version CodecVersion) (Codec, error) {
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
		return nil, fmt.Errorf("unsupported codec version: %v", version)
	}
}

// CodecFromConfig determines and returns the appropriate codec based on chain configuration, block number, and timestamp.
func CodecFromConfig(chainCfg *params.ChainConfig, startBlockNumber *big.Int, startBlockTimestamp uint64) Codec {
	if chainCfg.IsDarwinV2(startBlockNumber, startBlockTimestamp) {
		return &DACodecV4{}
	} else if chainCfg.IsDarwin(startBlockNumber, startBlockTimestamp) {
		return &DACodecV3{}
	} else if chainCfg.IsCurie(startBlockNumber) {
		return &DACodecV2{}
	} else if chainCfg.IsBernoulli(startBlockNumber) {
		return &DACodecV1{}
	} else {
		return &DACodecV0{}
	}
}
