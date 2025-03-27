package encoding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

type DACodecV7 struct{}

// Version returns the codec version.
func (d *DACodecV7) Version() CodecVersion {
	return CodecV7
}

// MaxNumChunksPerBatch returns the maximum number of chunks per batch.
func (d *DACodecV7) MaxNumChunksPerBatch() int {
	return math.MaxInt
}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (d *DACodecV7) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (DABlock, error) {
	return newDABlockV7FromBlockWithValidation(block, &totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
// Note: In DACodecV7 there is no notion of chunks. Blobs contain the entire batch data without any information of Chunks within.
// However, for compatibility reasons this function is implemented to create a DAChunk from a Chunk.
// This way we can still uniquely identify a set of blocks and their L1 messages.
func (d *DACodecV7) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
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

	if err := iterateAndVerifyBlocksAndL1Messages(chunk.PrevL1MessageQueueHash, chunk.PostL1MessageQueueHash, chunk.Blocks, &totalL1MessagePoppedBefore, func(initialBlockNumber uint64) {}, func(block *Block, daBlock *daBlockV7) error {
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
func (d *DACodecV7) NewDABatch(batch *Batch) (DABatch, error) {
	if len(batch.Blocks) == 0 {
		return nil, errors.New("batch must contain at least one block")
	}

	if err := checkBlocksBatchVSChunksConsistency(batch); err != nil {
		return nil, fmt.Errorf("failed to check blocks batch vs chunks consistency: %w", err)
	}

	blob, blobVersionedHash, blobBytes, err := d.constructBlob(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to construct blob: %w", err)
	}

	daBatch, err := newDABatchV7(CodecV7, batch.Index, blobVersionedHash, batch.ParentBatchHash, blob, blobBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to construct DABatch: %w", err)
	}

	return daBatch, nil
}

func (d *DACodecV7) constructBlob(batch *Batch) (*kzg4844.Blob, common.Hash, []byte, error) {
	blobBytes := make([]byte, blobEnvelopeV7OffsetPayload)

	payloadBytes, err := d.constructBlobPayload(batch)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	compressedPayloadBytes, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	isCompressedFlag := uint8(0x0)
	if enableCompression {
		isCompressedFlag = 0x1
		payloadBytes = compressedPayloadBytes
	}

	sizeSlice := encodeSize3Bytes(uint32(len(payloadBytes)))

	blobBytes[blobEnvelopeV7OffsetVersion] = uint8(CodecV7)
	copy(blobBytes[blobEnvelopeV7OffsetByteSize:blobEnvelopeV7OffsetCompressedFlag], sizeSlice)
	blobBytes[blobEnvelopeV7OffsetCompressedFlag] = isCompressedFlag
	blobBytes = append(blobBytes, payloadBytes...)

	if len(blobBytes) > maxEffectiveBlobBytes {
		log.Error("ConstructBlob: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return nil, common.Hash{}, nil, fmt.Errorf("blob exceeds maximum size: got %d, allowed %d", len(blobBytes), maxEffectiveBlobBytes)
	}

	// convert raw data to BLSFieldElements
	blob, err := makeBlobCanonical(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to convert blobBytes to canonical form: %w", err)
	}

	// compute blob versioned hash
	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to create blob commitment: %w", err)
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	return blob, blobVersionedHash, blobBytes, nil
}

func (d *DACodecV7) constructBlobPayload(batch *Batch) ([]byte, error) {
	blobPayload := blobPayloadV7{
		prevL1MessageQueueHash: batch.PrevL1MessageQueueHash,
		postL1MessageQueueHash: batch.PostL1MessageQueueHash,
		blocks:                 batch.Blocks,
	}

	return blobPayload.Encode()
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (d *DACodecV7) NewDABatchFromBytes(data []byte) (DABatch, error) {
	daBatch, err := decodeDABatchV7(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DA batch: %w", err)
	}

	if daBatch.version != CodecV7 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV7, daBatch.version)
	}

	return daBatch, nil
}

func (d *DACodecV7) NewDABatchFromParams(batchIndex uint64, blobVersionedHash, parentBatchHash common.Hash) (DABatch, error) {
	return newDABatchV7(CodecV7, batchIndex, blobVersionedHash, parentBatchHash, nil, nil)
}

func (d *DACodecV7) DecodeDAChunksRawTx(_ [][]byte) ([]*DAChunkRawTx, error) {
	return nil, errors.New("DecodeDAChunksRawTx is not implemented for DACodecV7, use DecodeBlob instead")
}

func (d *DACodecV7) DecodeBlob(blob *kzg4844.Blob) (DABlobPayload, error) {
	rawBytes := bytesFromBlobCanonical(blob)

	// read the blob envelope header
	version := rawBytes[blobEnvelopeV7OffsetVersion]
	if CodecVersion(version) != CodecV7 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV7, version)
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
		if payloadBytes, err = decompressV7Bytes(payloadBytes); err != nil {
			return nil, fmt.Errorf("failed to decompress blob payload: %w", err)
		}
	}

	// read the payload
	payload, err := decodeBlobPayloadV7(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob payload: %w", err)
	}

	return payload, nil
}

func (d *DACodecV7) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	return nil
}

// checkCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a blob payload, compresses the data, and checks the compressed data compatibility.
func (d *DACodecV7) checkCompressedDataCompatibility(payloadBytes []byte) ([]byte, bool, error) {
	compressedPayloadBytes, err := zstd.CompressScrollBatchBytes(payloadBytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to compress blob payload: %w", err)
	}

	if err = checkCompressedDataCompatibility(compressedPayloadBytes); err != nil {
		log.Warn("Compressed data compatibility check failed", "err", err, "payloadBytes", hex.EncodeToString(payloadBytes), "compressedPayloadBytes", hex.EncodeToString(compressedPayloadBytes))
		return nil, false, nil
	}

	// check if compressed data is bigger or equal to the original data -> no need to compress
	if len(compressedPayloadBytes) >= len(payloadBytes) {
		log.Warn("Compressed data is bigger or equal to the original data", "payloadBytes", hex.EncodeToString(payloadBytes), "compressedPayloadBytes", hex.EncodeToString(compressedPayloadBytes))
		return nil, false, nil
	}

	return compressedPayloadBytes, true, nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
// Note: For DACodecV7, this function is not implemented since there is no notion of DAChunk in this version. Blobs
// contain the entire batch data, and it is up to a prover to decide the chunk sizes.
func (d *DACodecV7) CheckChunkCompressedDataCompatibility(_ *Chunk) (bool, error) {
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (d *DACodecV7) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
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

	_, compatible, err := d.checkCompressedDataCompatibility(payloadBytes)
	if err != nil {
		return false, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	return compatible, nil
}

func (d *DACodecV7) estimateL1CommitBatchSizeAndBlobSize(batch *Batch) (uint64, uint64, error) {
	if len(batch.Blocks) == 0 {
		return 0, 0, errors.New("batch must contain at least one block")
	}

	blobBytes := make([]byte, blobEnvelopeV7OffsetPayload)

	payloadBytes, err := d.constructBlobPayload(batch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	compressedPayloadBytes, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes)
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
func (d *DACodecV7) EstimateChunkL1CommitBatchSizeAndBlobSize(chunk *Chunk) (uint64, uint64, error) {
	return d.estimateL1CommitBatchSizeAndBlobSize(&Batch{
		Blocks:                 chunk.Blocks,
		PrevL1MessageQueueHash: chunk.PrevL1MessageQueueHash,
		PostL1MessageQueueHash: chunk.PostL1MessageQueueHash,
	})
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV7) EstimateBatchL1CommitBatchSizeAndBlobSize(batch *Batch) (uint64, uint64, error) {
	return d.estimateL1CommitBatchSizeAndBlobSize(batch)
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
// Note: For CodecV7 calldata is constant independently of how many blocks or batches are submitted.
func (d *DACodecV7) EstimateBlockL1CommitCalldataSize(block *Block) (uint64, error) {
	return 0, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
// Note: For CodecV7 calldata is constant independently of how many blocks or batches are submitted. There is no notion
// of chunks in this version.
func (d *DACodecV7) EstimateChunkL1CommitCalldataSize(chunk *Chunk) (uint64, error) {
	return 0, nil
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
// Note: For CodecV7 calldata is constant independently of how many blocks or batches are submitted.
// Version + BatchHeader
func (d *DACodecV7) EstimateBatchL1CommitCalldataSize(batch *Batch) (uint64, error) {
	return 1 + daBatchV7EncodedLength, nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
// Note: For CodecV7 calldata is constant independently of how many blocks or batches are submitted. There is no notion
// of chunks in this version.
func (d *DACodecV7) EstimateChunkL1CommitGas(chunk *Chunk) (uint64, error) {
	return 0, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (d *DACodecV7) EstimateBatchL1CommitGas(batch *Batch) (uint64, error) {
	// TODO: adjust this after contracts are implemented
	var totalL1CommitGas uint64

	// Add extra gas costs
	totalL1CommitGas += extraGasCost           // constant to account for ops like _getAdmin, _implementation, _requireNotPaused, etc
	totalL1CommitGas += 4 * coldSloadGas       // 4 one-time cold sload for commitBatch
	totalL1CommitGas += sstoreGas              // 1 time sstore
	totalL1CommitGas += baseTxGas              // base gas for tx
	totalL1CommitGas += calldataNonZeroByteGas // version in calldata

	return totalL1CommitGas, nil
}

// JSONFromBytes converts the bytes to a DABatch and then marshals it to JSON.
func (d *DACodecV7) JSONFromBytes(data []byte) ([]byte, error) {
	batch, err := d.NewDABatchFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DABatch from bytes: %w", err)
	}

	jsonBytes, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DABatch to JSON, version %d, hash %s: %w", batch.Version(), batch.Hash(), err)
	}

	return jsonBytes, nil
}

// ChallengeDigestFromBlobBytes calculates the challenge digest from the given blob bytes.
func (d *DACodecV7) ChallengeDigestFromBlobBytes(blobBytes []byte) (common.Hash, error) {
	if len(blobBytes) > maxEffectiveBlobBytes {
		return common.Hash{}, fmt.Errorf("blob exceeds maximum size: got %d, allowed %d", len(blobBytes), maxEffectiveBlobBytes)
	}

	blob, err := makeBlobCanonical(blobBytes)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to convert blobBytes to canonical form: %w", err)
	}

	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to create blob commitment: %w", err)
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	paddedBlobBytes := make([]byte, maxEffectiveBlobBytes)
	copy(paddedBlobBytes, blobBytes)

	challengeDigest := crypto.Keccak256Hash(crypto.Keccak256(paddedBlobBytes), blobVersionedHash[:])
	return challengeDigest, nil
}
