package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

type DACodecV4 struct {
	DACodecV3
}

// Version returns the codec version.
func (d *DACodecV4) Version() CodecVersion {
	return CodecV4
}

// DecodeTxsFromBlob decodes txs from blob bytes and writes to chunks
func (d *DACodecV4) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	rawBytes := bytesFromBlobCanonical(blob)

	// if first byte is 1 - data compressed, 0 - not compressed
	if rawBytes[0] == 0x1 {
		batchBytes, err := decompressScrollBlobToBatch(append(zstdMagicNumber, rawBytes[1:]...))
		if err != nil {
			return err
		}
		return decodeTxsFromBytes(batchBytes, chunks, d.MaxNumChunksPerBatch())
	} else {
		return decodeTxsFromBytes(rawBytes[1:], chunks, d.MaxNumChunksPerBatch())
	}
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV4) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > d.MaxNumChunksPerBatch() {
		return nil, fmt.Errorf("too many chunks in batch: got %d, maximum allowed is %d", len(batch.Chunks), d.MaxNumChunksPerBatch())
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("batch must contain at least one chunk")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, errors.New("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := d.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	skippedL1MessageBitmap, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	enableCompression, err := d.CheckBatchCompressedDataCompatibility(batch)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := d.constructBlobPayload(batch.Chunks, d.MaxNumChunksPerBatch(), enableCompression)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	if totalL1MessagePoppedAfter < batch.TotalL1MessagePoppedBefore {
		return nil, fmt.Errorf("batch index: %d, totalL1MessagePoppedAfter (%d) is less than batch.TotalL1MessagePoppedBefore (%d)", batch.Index, totalL1MessagePoppedAfter, batch.TotalL1MessagePoppedBefore)
	}
	l1MessagePopped := totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore

	return newDABatchV3(
		CodecV4,                   // version
		batch.Index,               // batchIndex
		l1MessagePopped,           // l1MessagePopped
		totalL1MessagePoppedAfter, // totalL1MessagePopped
		lastBlock.Header.Time,     // lastBlockTimestamp
		dataHash,                  // dataHash
		batch.ParentBatchHash,     // parentBatchHash
		blobVersionedHash,         // blobVersionedHash
		skippedL1MessageBitmap,    // skippedL1MessageBitmap
		blob,                      // blob
		z,                         // z
		blobBytes,                 // blobBytes
	)
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields and skipped L1 message bitmap empty.
func (d *DACodecV4) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) != daBatchV3EncodedLength {
		return nil, fmt.Errorf("invalid data length for DABatch, expected %d bytes but got %d", daBatchV3EncodedLength, len(data))
	}

	if CodecVersion(data[daBatchOffsetVersion]) != CodecV4 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV4, data[daBatchOffsetVersion])
	}

	return newDABatchV3WithProof(
		CodecVersion(data[daBatchOffsetVersion]),                                                          // version
		binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV3OffsetL1MessagePopped]),             // batchIndex
		binary.BigEndian.Uint64(data[daBatchV3OffsetL1MessagePopped:daBatchV3OffsetTotalL1MessagePopped]), // l1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV3OffsetTotalL1MessagePopped:daBatchOffsetDataHash]),          // totalL1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV3OffsetLastBlockTimestamp:daBatchV3OffsetBlobDataProof]),     // lastBlockTimestamp
		common.BytesToHash(data[daBatchOffsetDataHash:daBatchV3OffsetBlobVersionedHash]),                  // dataHash
		common.BytesToHash(data[daBatchV3OffsetParentBatchHash:daBatchV3OffsetLastBlockTimestamp]),        // parentBatchHash
		common.BytesToHash(data[daBatchV3OffsetBlobVersionedHash:daBatchV3OffsetParentBatchHash]),         // blobVersionedHash
		nil, // skippedL1MessageBitmap
		nil, // blob
		nil, // z
		nil, // blobBytes
		[2]common.Hash{ // blobDataProof
			common.BytesToHash(data[daBatchV3OffsetBlobDataProof : daBatchV3OffsetBlobDataProof+kzgPointByteSize]),
			common.BytesToHash(data[daBatchV3OffsetBlobDataProof+kzgPointByteSize : daBatchV3EncodedLength]),
		},
	), nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (d *DACodecV4) constructBlobPayload(chunks []*Chunk, maxNumChunksPerBatch int, enableCompression bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + maxNumChunksPerBatch*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+maxNumChunksPerBatch+1)*common.HashLength)

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
				rlpTxData, err := convertTxDataToRLPEncoding(tx)
				if err != nil {
					return nil, common.Hash{}, nil, nil, fmt.Errorf("failed to convert txData to RLP encoding: %w", err)
				}
				batchBytes = append(batchBytes, rlpTxData...)
			}
		}

		// blob metadata: chunki_size
		chunkSize := len(batchBytes) - currentChunkStartIndex
		binary.BigEndian.PutUint32(batchBytes[2+4*chunkID:], uint32(chunkSize))

		// challenge: compute chunk data hash
		chunkDataHash = crypto.Keccak256Hash(batchBytes[currentChunkStartIndex:])
		copy(challengePreimage[common.HashLength+chunkID*common.HashLength:], chunkDataHash[:])
	}

	// if we have fewer than maxNumChunksPerBatch chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < maxNumChunksPerBatch; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[common.HashLength+chunkID*common.HashLength:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(batchBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	var blobBytes []byte
	if enableCompression {
		// blobBytes represents the compressed blob payload (batchBytes)
		var err error
		blobBytes, err = zstd.CompressScrollBatchBytes(batchBytes)
		if err != nil {
			return nil, common.Hash{}, nil, nil, err
		}
		// Check compressed data compatibility.
		if err = checkCompressedDataCompatibility(blobBytes); err != nil {
			log.Error("ConstructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
			return nil, common.Hash{}, nil, nil, err
		}
		blobBytes = append([]byte{1}, blobBytes...)
	} else {
		blobBytes = append([]byte{0}, batchBytes...)
	}

	if len(blobBytes) > maxEffectiveBlobBytes {
		log.Error("ConstructBlobPayload: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
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
		return nil, common.Hash{}, nil, nil, fmt.Errorf("failed to create blob commitment: %w", err)
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	// challenge: append blob versioned hash
	copy(challengePreimage[(1+maxNumChunksPerBatch)*common.HashLength:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), blsModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	if len(pointBytes) > kzgPointByteSize {
		return nil, common.Hash{}, nil, nil, fmt.Errorf("pointBytes length exceeds %d bytes, got %d bytes", kzgPointByteSize, len(pointBytes))
	}
	start := kzgPointByteSize - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, blobBytes, nil
}

func (d *DACodecV4) estimateL1CommitBatchSizeAndBlobSize(chunks []*Chunk) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob(chunks, d)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to construct batch payload in blob: %w", err)
	}
	var blobBytesLength uint64
	enableCompression, err := d.CheckBatchCompressedDataCompatibility(&Batch{Chunks: chunks})
	if err != nil {
		return 0, 0, fmt.Errorf("failed to compress scroll batch bytes: %w", err)
	}
	if enableCompression {
		blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
		if err != nil {
			return 0, 0, err
		}
		blobBytesLength = 1 + uint64(len(blobBytes))
	} else {
		blobBytesLength = 1 + uint64(len(batchBytes))
	}
	return uint64(len(batchBytes)), calculatePaddedBlobSize(blobBytesLength), nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a single chunk.
func (d *DACodecV4) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	return d.estimateL1CommitBatchSizeAndBlobSize([]*Chunk{c})
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV4) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	return d.estimateL1CommitBatchSizeAndBlobSize(b.Chunks)
}

// checkCompressedDataCompatibility checks the compressed data compatibility for a batch's chunks.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility.
func (d *DACodecV4) checkCompressedDataCompatibility(chunks []*Chunk) (bool, error) {
	batchBytes, err := constructBatchPayloadInBlob(chunks, d)
	if err != nil {
		return false, fmt.Errorf("failed to construct batch payload in blob: %w", err)
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, fmt.Errorf("failed to compress scroll batch bytes: %w", err)
	}
	if err = checkCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("Compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func (d *DACodecV4) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	return d.checkCompressedDataCompatibility([]*Chunk{c})
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (d *DACodecV4) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	return d.checkCompressedDataCompatibility(b.Chunks)
}

// JSONFromBytes converts the bytes to a daBatchV3 and then marshals it to JSON.
func (d *DACodecV4) JSONFromBytes(data []byte) ([]byte, error) {
	batch, err := d.NewDABatchFromBytes(data) // this is different from the V3 implementation
	if err != nil {
		return nil, fmt.Errorf("failed to decode DABatch from bytes: %w", err)
	}

	jsonBytes, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DABatch to JSON, version %d, hash %s: %w", batch.Version(), batch.Hash(), err)
	}

	return jsonBytes, nil
}
