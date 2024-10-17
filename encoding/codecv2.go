package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

type DACodecV2 struct {
	DACodecV1
}

// codecv2MaxNumChunks is the maximum number of chunks that a batch can contain.
const codecv2MaxNumChunks = 45

// Version returns the codec version.
func (d *DACodecV2) Version() CodecVersion {
	return CodecV2
}

// MaxNumChunksPerBatch returns the maximum number of chunks per batch.
func (d *DACodecV2) MaxNumChunksPerBatch() uint64 {
	return codecv2MaxNumChunks
}

// DecodeTxsFromBlob decodes txs from blob bytes and writes to chunks
func (d *DACodecV2) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	compressedBytes := bytesFromBlobCanonical(blob)
	magics := []byte{0x28, 0xb5, 0x2f, 0xfd}

	batchBytes, err := decompressScrollBlobToBatch(append(magics, compressedBytes[:]...))
	if err != nil {
		return err
	}
	return decodeTxsFromBytes(batchBytes, chunks, int(d.MaxNumChunksPerBatch()))
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV2) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > int(d.MaxNumChunksPerBatch()) {
		return nil, fmt.Errorf("too many chunks in batch: got %d, maximum allowed is %d", len(batch.Chunks), d.MaxNumChunksPerBatch())
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("batch must contain at least one chunk")
	}

	// batch data hash
	dataHash, err := d.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, _, err := d.constructBlobPayload(batch.Chunks, int(d.MaxNumChunksPerBatch()), false /* no mock */)
	if err != nil {
		return nil, err
	}

	if totalL1MessagePoppedAfter < batch.TotalL1MessagePoppedBefore {
		return nil, fmt.Errorf("totalL1MessagePoppedAfter (%d) is less than batch.TotalL1MessagePoppedBefore (%d)", totalL1MessagePoppedAfter, batch.TotalL1MessagePoppedBefore)
	}
	l1MessagePopped := totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore

	daBatch := newDABatchV1(
		uint8(CodecV2),            // version
		batch.Index,               // batchIndex
		l1MessagePopped,           // l1MessagePopped
		totalL1MessagePoppedAfter, // totalL1MessagePopped
		dataHash,                  // dataHash
		batch.ParentBatchHash,     // parentBatchHash
		blobVersionedHash,         // blobVersionedHash
		bitmapBytes,               // skippedL1MessageBitmap
		blob,                      // blob
		z,                         // z
	)

	return daBatch, nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (d *DACodecV2) constructBlobPayload(chunks []*Chunk, maxNumChunksPerBatch int, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + maxNumChunksPerBatch*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+maxNumChunksPerBatch+1)*32)

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
				rlpTxData, err := convertTxDataToRLPEncoding(tx, useMockTxData)
				if err != nil {
					return nil, common.Hash{}, nil, nil, err
				}
				batchBytes = append(batchBytes, rlpTxData...)
			}
		}

		// blob metadata: chunki_size
		chunkSize := len(batchBytes) - currentChunkStartIndex
		binary.BigEndian.PutUint32(batchBytes[2+4*chunkID:], uint32(chunkSize))

		// challenge: compute chunk data hash
		chunkDataHash = crypto.Keccak256Hash(batchBytes[currentChunkStartIndex:])
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// if we have fewer than MaxNumChunksPerBatch chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < maxNumChunksPerBatch; chunkID++ {
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
	if !useMockTxData && len(batchBytes) > minCompressedDataCheckSize {
		// Check compressed data compatibility.
		if err = checkCompressedDataCompatibility(blobBytes); err != nil {
			log.Error("constructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
			return nil, common.Hash{}, nil, nil, err
		}
	}

	if len(blobBytes) > maxEffectiveBlobBytes {
		log.Error("constructBlobPayload: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return nil, common.Hash{}, nil, nil, errors.New("Blob payload exceeds maximum size")
	}

	// convert raw data to BLSFieldElements
	blob, err := makeBlobCanonical(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, nil, fmt.Errorf("failed to convert blobBytes to canonical form: %w", err)
	}

	// compute blob versioned hash
	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return nil, common.Hash{}, nil, nil, errors.New("failed to create blob commitment")
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	// challenge: append blob versioned hash
	copy(challengePreimage[(1+maxNumChunksPerBatch)*32:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), blsModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	start := 32 - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, blobBytes, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (d *DACodecV2) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 121 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 121 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV2 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV2, data[0])
	}

	b := newDABatchV1(
		data[0],                              // version
		binary.BigEndian.Uint64(data[1:9]),   // batchIndex
		binary.BigEndian.Uint64(data[9:17]),  // l1MessagePopped
		binary.BigEndian.Uint64(data[17:25]), // totalL1MessagePopped
		common.BytesToHash(data[25:57]),      // dataHash
		common.BytesToHash(data[57:89]),      // blobVersionedHash
		common.BytesToHash(data[89:121]),     // parentBatchHash
		data[121:],                           // skippedL1MessageBitmap
		nil,                                  // blob
		nil,                                  // z
	)

	return b, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a single chunk.
func (d *DACodecV2) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob([]*Chunk{c}, d)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to construct batch payload in blob: %w", err)
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to compress scroll batch bytes: %w", err)
	}
	return uint64(len(batchBytes)), calculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV2) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob(b.Chunks, d)
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), calculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// checkCompressedDataCompatibility checks the compressed data compatibility for a batch's chunks.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility.
func (d *DACodecV2) checkCompressedDataCompatibility(chunks []*Chunk) (bool, error) {
	batchBytes, err := constructBatchPayloadInBlob(chunks, d)
	if err != nil {
		return false, fmt.Errorf("failed to construct batch payload in blob: %w", err)
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, fmt.Errorf("failed to compress scroll batch bytes: %w", err)
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= minCompressedDataCheckSize {
		return true, nil
	}
	if err = checkCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("Compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (d *DACodecV2) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	return d.checkCompressedDataCompatibility([]*Chunk{c})
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (d *DACodecV2) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	return d.checkCompressedDataCompatibility(b.Chunks)
}
