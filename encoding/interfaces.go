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
	BlobDataProofForPointEvaluation() ([]byte, error)
	Blob() *kzg4844.Blob
	BlobBytes() []byte
	BlobVersionedHashes() []common.Hash
}

// Codec represents the interface for encoding and decoding DA-related structures.
type Codec interface {
	Version() CodecVersion

	NewDABlock(*Block, uint64) (DABlock, error)
	NewDAChunk(*Chunk, uint64) (DAChunk, error)
	NewDABatch(*Batch) (DABatch, error)
	NewDABatchFromBytes([]byte) (DABatch, error)
	NewDABatchWithExpectedBlobVersionedHashes(*Batch, []common.Hash) (DABatch, error)

	DecodeDAChunks(chunks [][]byte) ([]DAChunk, error)

	EstimateChunkL1CommitBatchSizeAndBlobSize(*Chunk) (uint64, uint64, error)
	EstimateBatchL1CommitBatchSizeAndBlobSize(*Batch) (uint64, uint64, error)
	CheckChunkCompressedDataCompatibility(*Chunk) (bool, error)
	CheckBatchCompressedDataCompatibility(*Batch) (bool, error)
	EstimateChunkL1CommitCalldataSize(*Chunk) (uint64, error)
	EstimateChunkL1CommitGas(*Chunk) (uint64, error)
	EstimateBatchL1CommitGas(*Batch) (uint64, error)
	EstimateBatchL1CommitCalldataSize(*Batch) (uint64, error)

	SetCompression(enable bool)
	JSONFromBytes([]byte) ([]byte, error)
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

// MyCodecGen is a map that stores codec generator functions for each version.
var MyCodecGen = make(map[CodecVersion]func() Codec)

// RegisterCodec registers a codec generator function for a specific version.
func RegisterCodec(version CodecVersion, codecGenFunc func() Codec) {
	MyCodecGen[version] = codecGenFunc
}

// getCodec retrieves a Codec instance for the specified version.
// It returns an error if the version is not supported.
func getCodec(version CodecVersion) (Codec, error) {
	codecGen, ok := MyCodecGen[version]
	if !ok {
		return nil, fmt.Errorf("unsupported codec version: %d", version)
	}
	return codecGen(), nil
}

// CodecFromVersion returns the appropriate codec for the given version.
func CodecFromVersion(version CodecVersion) (Codec, error) {
	return getCodec(version)
}

// CodecFromConfig determines and returns the appropriate codec based on chain configuration, block number, and timestamp.
func CodecFromConfig(chainCfg *params.ChainConfig, startBlockNumber *big.Int, startBlockTimestamp uint64) (Codec, error) {
	var version CodecVersion
	if chainCfg.IsDarwinV2(startBlockTimestamp) {
		version = CodecV4
	} else if chainCfg.IsDarwin(startBlockTimestamp) {
		version = CodecV3
	} else if chainCfg.IsCurie(startBlockNumber) {
		version = CodecV2
	} else if chainCfg.IsBernoulli(startBlockNumber) {
		version = CodecV1
	} else {
		version = CodecV0
	}
	return getCodec(version)
}
