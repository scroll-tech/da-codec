package encoding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
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

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
// Note: In DACodecV8 there is no notion of chunks. Blobs contain the entire batch data without any information of Chunks within.
// However, for compatibility reasons this function is implemented to create a DAChunk from a Chunk.
// This way we can still uniquely identify a set of blocks and their L1 messages.
func (d *DACodecV8) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	if chunk == nil {
		return nil, errors.New("chunk is nil")
	}

	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > math.MaxUint16 {
		return nil, fmt.Errorf("number of blocks (%d) exceeds maximum allowed (%d)", len(chunk.Blocks), math.MaxUint16)
	}

	blocks := make([]DABlock, 0, len(chunk.Blocks))
	txs := make([][]*types.TransactionData, 0, len(chunk.Blocks))

	if err := iterateAndVerifyBlocksAndL1MessagesV8(chunk.PrevL1MessageQueueHash, chunk.PostL1MessageQueueHash, chunk.Blocks, &totalL1MessagePoppedBefore, func(initialBlockNumber uint64) {}, func(block *Block, daBlock *daBlockV8) error {
		blocks = append(blocks, daBlock)
		txs = append(txs, block.Transactions)

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to iterate and verify blocks and L1 messages: %w", err)
	}

	daChunk := newDAChunkV7(
		blocks,
		txs,
	)

	return daChunk, nil
}

// NewDABatch creates a DABatch including blob from the provided Batch.
func (d *DACodecV8) NewDABatch(batch *Batch) (DABatch, error) {
	start := time.Now()
	defer func() {
		log.Info("DACodecV8.NewDABatch completed", "duration", time.Since(start), "blocks", len(batch.Blocks), "start block number", batch.Blocks[0].Header.Number)
	}()

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

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func (d *DACodecV8) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	// filling the needed fields for the batch used in the check
	b := &Batch{
		Chunks:                 []*Chunk{c},
		PrevL1MessageQueueHash: c.PrevL1MessageQueueHash,
		PostL1MessageQueueHash: c.PostL1MessageQueueHash,
		Blocks:                 c.Blocks,
	}

	return d.CheckBatchCompressedDataCompatibility(b)
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
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

	// This check is only used for sanity checks. If the check fails, it means that the compression did not work as expected.
	// rollup-relayer will try popping the last chunk of the batch (or last block of the chunk when in proposing chunks) and try again to see if it works as expected.
	// Since length check is used for DA and proving efficiency, it does not need to be checked here.
	_, compatible, err := d.checkCompressedDataCompatibility(payloadBytes, true)
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

	log.Info("DACodecV8 compression statistics", "blocks", len(batch.Blocks), "startBlockHeight", batch.Blocks[0].Header.Number, "originalSize", len(payloadBytes), "compressedSize", len(compressedPayloadBytes), "enableCompression", enableCompression)

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
