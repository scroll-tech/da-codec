package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

type DACodecV4 struct {
	DACodecV3
	enableCompress bool
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
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
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
	bitmapBytes, totalL1MessagePoppedAfter, err := ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := d.constructBlobPayload(batch.Chunks, int(d.MaxNumChunksPerBatch()), false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	d.enableCompress, err = d.CheckBatchCompressedDataCompatibility(batch)
	if err != nil {
		return nil, err
	}

	return newDABatchV2(
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
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV4)
	}

	b := newDABatchV2WithProof(
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

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (d *DACodecV4) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob([]*Chunk{c}, d)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	enableCompress, err := d.CheckChunkCompressedDataCompatibility(c)
	if err != nil {
		return 0, 0, err
	}
	if enableCompress {
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

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (d *DACodecV4) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob(b.Chunks, d)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	enableCompress, err := d.CheckBatchCompressedDataCompatibility(b)
	if err != nil {
		return 0, 0, err
	}
	if enableCompress {
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
