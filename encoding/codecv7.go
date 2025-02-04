package encoding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/scroll-tech/go-ethereum/common"
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
	if !block.Header.Number.IsUint64() {
		return nil, errors.New("block number is not uint64")
	}

	numL1Messages, highestQueueIndex, err := block.NumL1MessagesNoSkipping()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate number of L1 messages: %w", err)
	}
	if totalL1MessagePoppedBefore+uint64(numL1Messages) != highestQueueIndex {
		return nil, fmt.Errorf("failed to sanity check L1 messages count: totalL1MessagePoppedBefore + numL1Messages != highestQueueIndex: %d + %d != %d", totalL1MessagePoppedBefore, numL1Messages, highestQueueIndex)
	}

	numL2Transactions := block.NumL2Transactions()
	numTransactions := uint64(numL1Messages) + numL2Transactions
	if numTransactions > math.MaxUint16 {
		return nil, errors.New("number of transactions exceeds max uint16")
	}

	daBlock := newDABlockV7(
		block.Header.Number.Uint64(), // number
		block.Header.Time,            // timestamp
		block.Header.BaseFee,         // baseFee
		block.Header.GasLimit,        // gasLimit
		uint16(numTransactions),      // numTransactions
		numL1Messages,                // numL1Messages
	)

	return daBlock, nil
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
// Note: For DACodecV7, this function is not implemented since there is no notion of DAChunk in this version. Blobs
// contain the entire batch data without any information of Chunks within.
func (d *DACodecV7) NewDAChunk(_ *Chunk, _ uint64) (DAChunk, error) {
	return nil, nil
}

// NewDABatch creates a DABatch including blob from the provided Batch.
func (d *DACodecV7) NewDABatch(batch *Batch) (DABatch, error) {
	if len(batch.Chunks) != 0 {
		return nil, errors.New("batch must not contain any chunks")
	}

	if len(batch.Blocks) == 0 {
		return nil, errors.New("batch must contain at least one block")
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
	blobBytes[blobEnvelopeV7OffsetVersion] = uint8(CodecV7)

	payloadBytes, err := d.constructBlobPayload(batch)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to construct blob payload: %w", err)
	}

	compressedPayloadBytes, enableCompression, err := d.checkCompressedDataCompatibility(payloadBytes)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to check batch compressed data compatibility: %w", err)
	}

	if enableCompression {
		blobBytes[blobEnvelopeV7OffsetCompressedFlag] = 0x1
		payloadBytes = compressedPayloadBytes
	} else {
		blobBytes[blobEnvelopeV7OffsetCompressedFlag] = 0x0
	}

	sizeSlice := encodeSize3Bytes(uint32(len(payloadBytes)))
	copy(blobBytes[blobEnvelopeV7OffsetByteSize:blobEnvelopeV7OffsetCompressedFlag], sizeSlice)
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
		initialL1MessageIndex:     batch.InitialL1MessageIndex,
		initialL1MessageQueueHash: batch.InitialL1MessageQueueHash,
		lastL1MessageQueueHash:    batch.LastL1MessageQueueHash,
		blocks:                    batch.Blocks,
	}

	return blobPayload.Encode()
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields and skipped L1 message bitmap empty.
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
	return nil, nil
}

func (d *DACodecV7) DecodeBlob(blob *kzg4844.Blob) (DABlobPayload, error) {
	rawBytes := bytesFromBlobCanonical(blob)

	// read the blob envelope header
	version := rawBytes[blobEnvelopeV7OffsetVersion]
	if CodecVersion(version) != CodecV7 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV7, version)
	}

	// read the data size
	blobEnvelopeSize := decodeSize3Bytes(rawBytes[blobEnvelopeV7OffsetByteSize:blobEnvelopeV7OffsetCompressedFlag])
	if blobEnvelopeSize+blobEnvelopeV7OffsetPayload > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("blob envelope size exceeds the raw data size: %d > %d", blobEnvelopeSize, len(rawBytes))
	}

	payloadBytes := rawBytes[blobEnvelopeV7OffsetPayload : blobEnvelopeV7OffsetPayload+blobEnvelopeSize]

	// read the compressed flag and decompress if needed
	compressed := rawBytes[blobEnvelopeV7OffsetCompressedFlag]
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
	if len(b.Chunks) != 0 {
		return false, errors.New("batch must not contain any chunks")
	}

	if len(b.Blocks) == 0 {
		return false, errors.New("batch must contain at least one block")
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

// TODO: which of the Estimate* functions are needed?

func (d *DACodecV7) EstimateChunkL1CommitBatchSizeAndBlobSize(chunk *Chunk) (uint64, uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
}

func (d *DACodecV7) EstimateBatchL1CommitBatchSizeAndBlobSize(batch *Batch) (uint64, uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
}

func (d *DACodecV7) EstimateBlockL1CommitCalldataSize(block *Block) (uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
}

func (d *DACodecV7) EstimateChunkL1CommitCalldataSize(chunk *Chunk) (uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
}

func (d *DACodecV7) EstimateChunkL1CommitGas(chunk *Chunk) (uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
}

func (d *DACodecV7) EstimateBatchL1CommitGas(batch *Batch) (uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
}

func (d *DACodecV7) EstimateBatchL1CommitCalldataSize(batch *Batch) (uint64, error) {
	//TODO implement me after contracts are implemented
	panic("implement me")
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
