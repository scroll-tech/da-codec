package encoding

import (
	"encoding/json"
	"fmt"

	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

type DACodecV6 struct {
	DACodecV4
}

// Version returns the codec version.
func (d *DACodecV6) Version() CodecVersion {
	return CodecV6
}

// MaxNumChunksPerBatch returns the maximum number of chunks per batch.
func (d *DACodecV6) MaxNumChunksPerBatch() int {
	return 1
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
// Note: For DACodecV6, this function is not implemented since there is no notion of DAChunk in this version. Blobs
// contain the entire batch data, and it is up to a prover to decide the chunk sizes.
func (d *DACodecV6) NewDAChunk(_ *Chunk, _ uint64) (DAChunk, error) {
	return nil, nil
}

// NewDABatch creates a DABatch including blob from the provided Batch.
func (d *DACodecV6) NewDABatch(batch *Batch) (DABatch, error) {
	// TODO: create DABatch from the provided batch once the blob layout is defined. See DACodecV4 for reference.
	return nil, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields and skipped L1 message bitmap empty.
func (d *DACodecV6) NewDABatchFromBytes(data []byte) (DABatch, error) {
	daBatch, err := decodeDABatchV6(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DA batch: %w", err)
	}

	if daBatch.version != CodecV6 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV6, daBatch.version)
	}

	return daBatch, nil
}

func (d *DACodecV6) DecodeDAChunksRawTx(chunkBytes [][]byte) ([]*DAChunkRawTx, error) {
	return nil, nil
}

func (d *DACodecV6) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	return nil
}

// TODO: add DecodeBlob to interface to decode the blob and transactions or reuse DecodeTxsFromBlob but only have a single "chunk" for all transactions in the batch?

// TODO: which of the Estimate* functions are needed?

// JSONFromBytes converts the bytes to a DABatch and then marshals it to JSON.
func (d *DACodecV6) JSONFromBytes(data []byte) ([]byte, error) {
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
