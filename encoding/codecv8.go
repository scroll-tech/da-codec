package encoding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/scroll-tech/da-codec/encoding/zstd"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"
)

// DACodecV8 uses zstd.CompressScrollBatchBytesStandard for compression instead of zstd.CompressScrollBatchBytesLegacy.
//
// Note: Due to Go's method receiver behavior, we need to override all methods that call checkCompressedDataCompatibility.
// When a method in DACodecV7 calls d.checkCompressedDataCompatibility(), it will always use DACodecV7's version,
// even if the instance is actually a DACodecV8. Therefore, we must override:
// - checkCompressedDataCompatibility (core method using the new compression)
// - constructBlob (calls checkCompressedDataCompatibility)
// - NewDABatch (calls constructBlob)
// - CheckBatchCompressedDataCompatibility (calls checkCompressedDataCompatibility)
// - estimateL1CommitBatchSizeAndBlobSize (calls checkCompressedDataCompatibility)
// - EstimateChunkL1CommitBatchSizeAndBlobSize (calls estimateL1CommitBatchSizeAndBlobSize)
// - EstimateBatchL1CommitBatchSizeAndBlobSize (calls estimateL1CommitBatchSizeAndBlobSize)
type DACodecV8 struct {
	DACodecV7
}

func NewDACodecV8() *DACodecV8 {
	v := CodecV8
	return &DACodecV8{
		DACodecV7: DACodecV7{
			forcedVersion: &v,
		},
	}
}

// checkCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a blob payload, compresses the data, and checks the compressed data compatibility.
// flag checkLength indicates whether to check the length of the compressed data against the original data.
// If checkLength is true, this function returns if compression is needed based on the compressed data's length, which is used when doing batch bytes encoding.
// If checkLength is false, this function returns the result of the compatibility check, which is used when determining the chunk and batch contents.
func (d *DACodecV8) checkCompressedDataCompatibility(payloadBytes []byte, checkLength bool) ([]byte, bool, error) {
	compressedPayloadBytes, err := zstd.CompressScrollBatchBytesStandard(payloadBytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to compress blob payload: %w", err)
	}

	if err = checkCompressedDataCompatibilityV8(compressedPayloadBytes); err != nil {
		log.Warn("Compressed data compatibility check failed", "err", err, "payloadBytes", hex.EncodeToString(payloadBytes), "compressedPayloadBytes", hex.EncodeToString(compressedPayloadBytes))
		return nil, false, nil
	}

	// check if compressed data is bigger or equal to the original data -> no need to compress
	if checkLength && len(compressedPayloadBytes) >= len(payloadBytes) {
		log.Warn("Compressed data is bigger or equal to the original data", "payloadBytes", hex.EncodeToString(payloadBytes), "compressedPayloadBytes", hex.EncodeToString(compressedPayloadBytes))
		return nil, false, nil
	}

	return compressedPayloadBytes, true, nil
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

	daBatch, err := newDABatchV7(d.Version(), batch.Index, blobVersionedHash, batch.ParentBatchHash, blob, blobBytes, challengeDigest)
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

	compressedPayloadBytes, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes, true /* checkLength */)
	if err != nil {
		return nil, common.Hash{}, nil, common.Hash{}, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	isCompressedFlag := uint8(0x0)
	if enableCompression {
		isCompressedFlag = 0x1
		payloadBytes = compressedPayloadBytes
	}

	sizeSlice := encodeSize3Bytes(uint32(len(payloadBytes)))

	blobBytes[blobEnvelopeV7OffsetVersion] = uint8(d.Version())
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

	// compute challenge digest for codecv7, different from previous versions,
	// the blob bytes are padded to the max effective blob size, which is 131072 / 32 * 31 due to the blob encoding
	paddedBlobBytes := make([]byte, maxEffectiveBlobBytes)
	copy(paddedBlobBytes, blobBytes)

	challengeDigest := crypto.Keccak256Hash(crypto.Keccak256(paddedBlobBytes), blobVersionedHash[:])

	return blob, blobVersionedHash, blobBytes, challengeDigest, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (d *DACodecV8) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	if len(b.Blocks) == 0 {
		return false, errors.New("batch must contain at least one block")
	}

	if err := checkBlocksBatchVSChunksConsistency(b); err != nil {
		return false, fmt.Errorf("failed to check blocks batch vs chunks consistency: %w", err)
	}

	payloadBytes, err := d.constructBlobPayload(b)
	if err != nil {
		return false, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	// This check is only used for sanity checks. If the check fails, it means that the compression did not work as expected.
	// rollup-relayer will try popping the last chunk of the batch (or last block of the chunk when in proposing chunks) and try again to see if it works as expected.
	// Since length check is used for DA and proving efficiency, it does not need to be checked here.
	_, compatible, err := d.checkCompressedDataCompatibility(payloadBytes, false /* checkLength */)
	if err != nil {
		return false, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	return compatible, nil
}

func (d *DACodecV8) estimateL1CommitBatchSizeAndBlobSize(batch *Batch) (uint64, uint64, error) {
	if len(batch.Blocks) == 0 {
		return 0, 0, errors.New("batch must contain at least one block")
	}

	blobBytes := make([]byte, blobEnvelopeV7OffsetPayload)

	payloadBytes, err := d.constructBlobPayload(batch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	compressedPayloadBytes, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes, true /* checkLength */)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	if enableCompression {
		blobBytes = append(blobBytes, compressedPayloadBytes...)
	} else {
		blobBytes = append(blobBytes, payloadBytes...)
	}

	return blobEnvelopeV7OffsetPayload + uint64(len(payloadBytes)), calculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a single chunk.
func (d *DACodecV8) EstimateChunkL1CommitBatchSizeAndBlobSize(chunk *Chunk) (uint64, uint64, error) {
	return d.estimateL1CommitBatchSizeAndBlobSize(&Batch{
		Blocks:                 chunk.Blocks,
		PrevL1MessageQueueHash: chunk.PrevL1MessageQueueHash,
		PostL1MessageQueueHash: chunk.PostL1MessageQueueHash,
	})
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV8) EstimateBatchL1CommitBatchSizeAndBlobSize(batch *Batch) (uint64, uint64, error) {
	return d.estimateL1CommitBatchSizeAndBlobSize(batch)
}
