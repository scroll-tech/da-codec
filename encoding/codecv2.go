package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

type DACodecV2 struct{}

// Codecv2MaxNumChunks is the maximum number of chunks that a batch can contain.
const Codecv2MaxNumChunks = 45

// NewDABlock creates a new DABlock from the given encoding.Block and the total number of L1 messages popped before.
func (o *DACodecV2) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (*DABlock, error) {
	return (&DACodecV1{}).NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given encoding.Chunk and the total number of L1 messages popped before.
func (o *DACodecV2) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	return (&DACodecV1{}).NewDAChunk(chunk, totalL1MessagePoppedBefore)
}

// NewDABatch creates a DABatch from the provided encoding.Batch.
func (o *DACodecV2) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > Codecv2MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
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
	blob, blobVersionedHash, z, _, err := o.constructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	daBatch := DABatchV2{
		DABatchBase: DABatchBase{
			Version:                uint8(CodecV2),
			BatchIndex:             batch.Index,
			L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
			TotalL1MessagePopped:   totalL1MessagePoppedAfter,
			DataHash:               dataHash,
			ParentBatchHash:        batch.ParentBatchHash,
			SkippedL1MessageBitmap: bitmapBytes,
		},
		BlobVersionedHash: blobVersionedHash,
		blob:              blob,
		z:                 z,
	}

	return &daBatch, nil
}

// NewDABatchWithExpectedBlobVersionedHashes creates a DABatch from the provided Batch.
// It also checks if the blob versioned hashes are as expected.
func (o *DACodecV2) NewDABatchWithExpectedBlobVersionedHashes(batch *Batch, hashes []common.Hash) (DABatch, error) {
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
func (o *DACodecV2) constructBlobPayload(chunks []*Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + Codecv2MaxNumChunks*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+Codecv2MaxNumChunks+1)*32)

	// the chunk data hash used for calculating the challenge preimage
	var chunkDataHash common.Hash

	// blob metadata: num_chunks
	binary.BigEndian.PutUint16(batchBytes[0:], uint16(len(chunks)))

	// encode blob metadata and L2 transactions,
	// and simultaneously also build challenge preimage
	for chunkID, chunk := range chunks {
		currentChunkStartIndex := len(batchBytes)

		for _, block := range chunk.Blocks {
			for _, tx := range block.Transactions {
				if tx.Type == types.L1MessageTxType {
					continue
				}

				// encode L2 txs into blob payload
				rlpTxData, err := ConvertTxDataToRLPEncoding(tx, useMockTxData)
				if err != nil {
					return nil, common.Hash{}, nil, nil, err
				}
				batchBytes = append(batchBytes, rlpTxData...)
			}
		}

		// blob metadata: chunki_size
		if chunkSize := len(batchBytes) - currentChunkStartIndex; chunkSize != 0 {
			binary.BigEndian.PutUint32(batchBytes[2+4*chunkID:], uint32(chunkSize))
		}

		// challenge: compute chunk data hash
		chunkDataHash = crypto.Keccak256Hash(batchBytes[currentChunkStartIndex:])
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// if we have fewer than Codecv2MaxNumChunks chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < Codecv2MaxNumChunks; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(batchBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	// blobBytes represents the compressed blob payload (batchBytes)
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return nil, common.Hash{}, nil, nil, err
	}

	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if !useMockTxData && len(batchBytes) > 131072 {
		// Check compressed data compatibility.
		if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
			log.Error("constructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
			return nil, common.Hash{}, nil, nil, err
		}
	}

	if len(blobBytes) > 126976 {
		log.Error("constructBlobPayload: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return nil, common.Hash{}, nil, nil, errors.New("Blob payload exceeds maximum size")
	}

	// convert raw data to BLSFieldElements
	blob, err := MakeBlobCanonical(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, nil, err
	}

	// compute blob versioned hash
	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return nil, common.Hash{}, nil, nil, errors.New("failed to create blob commitment")
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	// challenge: append blob versioned hash
	copy(challengePreimage[(1+Codecv2MaxNumChunks)*32:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), BLSModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	start := 32 - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, blobBytes, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (o *DACodecV2) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 121 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 121 bytes but got %d", len(data))
	}

	b := &DABatchV2{
		DABatchBase: DABatchBase{
			Version:                data[0],
			BatchIndex:             binary.BigEndian.Uint64(data[1:9]),
			L1MessagePopped:        binary.BigEndian.Uint64(data[9:17]),
			TotalL1MessagePopped:   binary.BigEndian.Uint64(data[17:25]),
			DataHash:               common.BytesToHash(data[25:57]),
			ParentBatchHash:        common.BytesToHash(data[89:121]),
			SkippedL1MessageBitmap: data[121:],
		},
		BlobVersionedHash: common.BytesToHash(data[57:89]),
	}

	return b, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (o *DACodecV2) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	batchBytes, err := ConstructBatchPayloadInBlob([]*Chunk{c}, Codecv2MaxNumChunks)
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), CalculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (o *DACodecV2) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	batchBytes, err := ConstructBatchPayloadInBlob(b.Chunks, Codecv2MaxNumChunks)
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), CalculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (o *DACodecV2) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	batchBytes, err := ConstructBatchPayloadInBlob([]*Chunk{c}, Codecv2MaxNumChunks)
	if err != nil {
		return false, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= 131072 {
		return true, nil
	}
	if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckChunkCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (o *DACodecV2) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	batchBytes, err := ConstructBatchPayloadInBlob(b.Chunks, Codecv2MaxNumChunks)
	if err != nil {
		return false, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= 131072 {
		return true, nil
	}
	if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckBatchCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (o *DACodecV2) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return (&DACodecV1{}).EstimateChunkL1CommitCalldataSize(c)
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (o *DACodecV2) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	return (&DACodecV1{}).EstimateBatchL1CommitCalldataSize(b)
}

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func (o *DACodecV2) EstimateBlockL1CommitGas(b *Block) (uint64, error) {
	return (&DACodecV1{}).EstimateBlockL1CommitGas(b)
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (o *DACodecV2) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	return (&DACodecV1{}).EstimateChunkL1CommitGas(c)
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (o *DACodecV2) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	return (&DACodecV1{}).EstimateBatchL1CommitGas(b)
}

// SetCompression enables or disables compression.
func (o *DACodecV2) SetCompression(enable bool) {}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func (o *DACodecV2) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	return (&DACodecV1{}).computeBatchDataHash(chunks, totalL1MessagePoppedBefore)
}

// DecodeDAChunks takes a byte slice and decodes it into a []DAChunk
func (o *DACodecV2) DecodeDAChunks(bytes [][]byte) ([]DAChunk, error) {
	return (&DACodecV1{}).DecodeDAChunks(bytes)
}
