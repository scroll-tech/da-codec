package encoding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"
)

type DACodecV8 struct {
	*DACodecV7
}

// NewDACodecV8 creates a new instance of DACodecV8.
func NewDACodecV8() *DACodecV8 {
	return &DACodecV8{
		DACodecV7: &DACodecV7{},
	}
}

// Version returns the codec version.
func (d *DACodecV8) Version() CodecVersion {
	return CodecV8
}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (d *DACodecV8) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (DABlock, error) {
	return newDABlockV8FromBlockWithValidation(block, &totalL1MessagePoppedBefore)
}

// NewDABatch creates a DABatch including blob from the provided Batch.
func (d *DACodecV8) NewDABatch(batch *Batch) (DABatch, error) {
	if len(batch.Blocks) == 0 {
		return nil, errors.New("batch must contain at least one block")
	}

	if err := checkBlocksBatchVSChunksConsistency(batch); err != nil {
		return nil, fmt.Errorf("failed to check blocks batch vs chunks consistency: %w", err)
	}

	blob, blobVersionedHash, blobBytes, challengeDigest, err := d.constructBlob(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to construct blob: %w", err)
	}

	daBatch, err := newDABatchV8(CodecV8, batch.Index, blobVersionedHash, batch.ParentBatchHash, blob, blobBytes, challengeDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to construct DABatch: %w", err)
	}

	return daBatch, nil
}

func (d *DACodecV8) constructBlob(batch *Batch) (*kzg4844.Blob, common.Hash, []byte, common.Hash, error) {
	blobBytes := make([]byte, blobEnvelopeV7OffsetPayload)

	payloadBytes, err := d.constructBlobPayload(batch)
	if err != nil {
		return nil, common.Hash{}, nil, common.Hash{}, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	// Use standard zstd compression for V8
	compressedPayloadBytes, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes, true)
	if err != nil {
		return nil, common.Hash{}, nil, common.Hash{}, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	isCompressedFlag := uint8(0x0)
	if enableCompression {
		isCompressedFlag = 0x1
		payloadBytes = compressedPayloadBytes
	}

	sizeSlice := encodeSize3Bytes(uint32(len(payloadBytes)))

	blobBytes[blobEnvelopeV7OffsetVersion] = uint8(CodecV8)
	copy(blobBytes[blobEnvelopeV7OffsetByteSize:blobEnvelopeV7OffsetCompressedFlag], sizeSlice)
	blobBytes[blobEnvelopeV7OffsetCompressedFlag] = isCompressedFlag
	blobBytes = append(blobBytes, payloadBytes...)

	if len(blobBytes) > maxEffectiveBlobBytes {
		log.Error("ConstructBlob: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return nil, common.Hash{}, nil, common.Hash{}, fmt.Errorf("blob exceeds maximum size: got %d, allowed %d", len(blobBytes), maxEffectiveBlobBytes)
	}

	// convert raw data to BLSFieldElements
	blob, err := makeBlobCanonical(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, common.Hash{}, fmt.Errorf("failed to convert blobBytes to canonical form: %w", err)
	}

	// compute blob versioned hash
	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return nil, common.Hash{}, nil, common.Hash{}, fmt.Errorf("failed to create blob commitment: %w", err)
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	// compute challenge digest
	paddedBlobBytes := make([]byte, maxEffectiveBlobBytes)
	copy(paddedBlobBytes, blobBytes)
	challengeDigest := crypto.Keccak256Hash(crypto.Keccak256(paddedBlobBytes), blobVersionedHash[:])

	return blob, blobVersionedHash, blobBytes, challengeDigest, nil
}

func (d *DACodecV8) constructBlobPayload(batch *Batch) ([]byte, error) {
	blobPayload := &blobPayloadV8{
		blobPayloadV7: &blobPayloadV7{
			prevL1MessageQueueHash: batch.PrevL1MessageQueueHash,
			postL1MessageQueueHash: batch.PostL1MessageQueueHash,
			blocks:                 batch.Blocks,
		},
	}

	return blobPayload.Encode()
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (d *DACodecV8) NewDABatchFromBytes(data []byte) (DABatch, error) {
	daBatch, err := decodeDABatchV8(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DA batch: %w", err)
	}

	if daBatch.version != CodecV8 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV8, daBatch.version)
	}

	return daBatch, nil
}

func (d *DACodecV8) NewDABatchFromParams(batchIndex uint64, blobVersionedHash, parentBatchHash common.Hash) (DABatch, error) {
	return newDABatchV8(CodecV8, batchIndex, blobVersionedHash, parentBatchHash, nil, nil, common.Hash{})
}

func (d *DACodecV8) DecodeBlob(blob *kzg4844.Blob) (DABlobPayload, error) {
	rawBytes := bytesFromBlobCanonical(blob)

	// read the blob envelope header
	version := rawBytes[blobEnvelopeV7OffsetVersion]
	if CodecVersion(version) != CodecV8 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV8, version)
	}

	// read the data size
	blobPayloadSize := decodeSize3Bytes(rawBytes[blobEnvelopeV7OffsetByteSize:blobEnvelopeV7OffsetCompressedFlag])
	if blobPayloadSize+blobEnvelopeV7OffsetPayload > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("blob envelope size exceeds the raw data size: %d > %d", blobPayloadSize, len(rawBytes))
	}

	payloadBytes := rawBytes[blobEnvelopeV7OffsetPayload : blobEnvelopeV7OffsetPayload+blobPayloadSize]

	// read the compressed flag and decompress if needed
	compressed := rawBytes[blobEnvelopeV7OffsetCompressedFlag]
	if compressed != 0x0 && compressed != 0x1 {
		return nil, fmt.Errorf("invalid compressed flag: %d", compressed)
	}
	if compressed == 0x1 {
		var err error
		// v8's payload is compressed the same way as v7
		if payloadBytes, err = decompressV7Bytes(payloadBytes); err != nil {
			return nil, fmt.Errorf("failed to decompress blob payload: %w", err)
		}
	}

	// read the payload
	payload, err := decodeBlobPayloadV8(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob payload: %w", err)
	}

	return payload, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV8) EstimateBatchL1CommitBatchSizeAndBlobSize(batch *Batch) (uint64, uint64, error) {
	daBatch, err := d.NewDABatch(batch)
	if err != nil {
		return 0, 0, err
	}

	batchBytes := daBatch.Encode()
	blobBytes := daBatch.BlobBytes()

	return uint64(len(batchBytes)), uint64(len(blobBytes)), nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a chunk.
func (d *DACodecV8) EstimateChunkL1CommitBatchSizeAndBlobSize(chunk *Chunk) (uint64, uint64, error) {
	// Create a temporary batch for the chunk
	batch := &Batch{
		Index:                      0,
		PrevL1MessageQueueHash:     chunk.PrevL1MessageQueueHash,
		PostL1MessageQueueHash:     chunk.PostL1MessageQueueHash,
		ParentBatchHash:            common.Hash{},
		Chunks:                     []*Chunk{chunk},
		Blocks:                     chunk.Blocks,
		TotalL1MessagePoppedBefore: 0,
	}

	return d.EstimateBatchL1CommitBatchSizeAndBlobSize(batch)
}

// CheckBatchCompressedDataCompatibility checks if the batch compressed data is compatible.
func (d *DACodecV8) CheckBatchCompressedDataCompatibility(batch *Batch) (bool, error) {
	if len(batch.Blocks) == 0 {
		return false, errors.New("batch must contain at least one block")
	}

	if err := checkBlocksBatchVSChunksConsistency(batch); err != nil {
		return false, fmt.Errorf("failed to check blocks batch vs chunks consistency: %w", err)
	}

	payloadBytes, err := d.constructBlobPayload(batch)
	if err != nil {
		return false, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	// Use standard zstd compression for V8
	_, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes, true)
	if err != nil {
		return false, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	return enableCompression, nil
}

// CheckChunkCompressedDataCompatibility checks if the chunk compressed data is compatible.
func (d *DACodecV8) CheckChunkCompressedDataCompatibility(chunk *Chunk) (bool, error) {
	// Create a temporary batch for the chunk
	batch := &Batch{
		Index:                      0,
		PrevL1MessageQueueHash:     chunk.PrevL1MessageQueueHash,
		PostL1MessageQueueHash:     chunk.PostL1MessageQueueHash,
		ParentBatchHash:            common.Hash{},
		Chunks:                     []*Chunk{chunk},
		Blocks:                     chunk.Blocks,
		TotalL1MessagePoppedBefore: 0,
	}

	return d.CheckBatchCompressedDataCompatibility(batch)
}
