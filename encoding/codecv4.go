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
		magics := []byte{0x28, 0xb5, 0x2f, 0xfd}
		batchBytes, err := decompressScrollBlobToBatch(append(magics, rawBytes[1:]...))
		if err != nil {
			return err
		}
		return decodeTxsFromBytes(batchBytes, chunks, int(d.MaxNumChunksPerBatch()))
	} else {
		return decodeTxsFromBytes(rawBytes[1:], chunks, int(d.MaxNumChunksPerBatch()))
	}
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV4) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > int(d.MaxNumChunksPerBatch()) {
		return nil, fmt.Errorf("too many chunks in batch: got %d, max allowed is %d", len(batch.Chunks), d.MaxNumChunksPerBatch())
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
	bitmapBytes, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	enableCompression, err := d.CheckBatchCompressedDataCompatibility(batch)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := d.constructBlobPayload(batch.Chunks, int(d.MaxNumChunksPerBatch()), enableCompression, false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	return newDABatchV3(
		uint8(CodecV4), // version
		batch.Index,    // batchIndex
		totalL1MessagePoppedAfter-batch.TotalL1MessagePoppedBefore, // l1MessagePopped
		totalL1MessagePoppedAfter,                                  // totalL1MessagePopped
		lastBlock.Header.Time,                                      // lastBlockTimestamp
		dataHash,                                                   // dataHash
		batch.ParentBatchHash,                                      // parentBatchHash
		blobVersionedHash,                                          // blobVersionedHash
		bitmapBytes,                                                // skippedL1MessageBitmap
		blob,                                                       // blob
		z,                                                          // z
		blobBytes,                                                  // blobBytes
	)
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (d *DACodecV4) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) != 193 {
		return nil, fmt.Errorf("invalid data length for DABatch, expected 193 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV4 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV4, data[0])
	}

	b := newDABatchV3WithProof(
		data[0],                                // Version
		binary.BigEndian.Uint64(data[1:9]),     // BatchIndex
		binary.BigEndian.Uint64(data[9:17]),    // L1MessagePopped
		binary.BigEndian.Uint64(data[17:25]),   // TotalL1MessagePopped
		binary.BigEndian.Uint64(data[121:129]), // LastBlockTimestamp
		common.BytesToHash(data[25:57]),        // DataHash
		common.BytesToHash(data[89:121]),       // ParentBatchHash
		common.BytesToHash(data[57:89]),        // BlobVersionedHash
		nil,                                    // skippedL1MessageBitmap
		nil,                                    // blob
		nil,                                    // z
		nil,                                    // blobBytes
		[2]common.Hash{ // BlobDataProof
			common.BytesToHash(data[129:161]),
			common.BytesToHash(data[161:193]),
		},
	)

	return b, nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (d *DACodecV4) constructBlobPayload(chunks []*Chunk, maxNumChunksPerBatch int, enableCompression bool, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
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

	// if we have fewer than maxNumChunksPerBatch chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < maxNumChunksPerBatch; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
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
		if !useMockTxData {
			// Check compressed data compatibility.
			if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
				log.Error("ConstructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
				return nil, common.Hash{}, nil, nil, err
			}
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
		return nil, common.Hash{}, nil, nil, err
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

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a single chunk.
func (d *DACodecV4) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob([]*Chunk{c}, d)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	enableCompression, err := d.CheckChunkCompressedDataCompatibility(c)
	if err != nil {
		return 0, 0, err
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

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV4) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob(b.Chunks, d)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	enableCompression, err := d.CheckBatchCompressedDataCompatibility(b)
	if err != nil {
		return 0, 0, err
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

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (d *DACodecV4) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	batchBytes, err := constructBatchPayloadInBlob([]*Chunk{c}, d)
	if err != nil {
		return false, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckChunkCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (d *DACodecV4) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	batchBytes, err := constructBatchPayloadInBlob(b.Chunks, d)
	if err != nil {
		return false, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckBatchCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}
