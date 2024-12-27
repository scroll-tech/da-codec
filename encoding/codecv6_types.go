package encoding

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// daBatchV3 contains metadata about a batch of DAChunks.
type daBatchV6 struct {
	version           CodecVersion
	batchIndex        uint64
	parentBatchHash   common.Hash
	blobVersionedHash common.Hash

	blob      *kzg4844.Blob
	z         *kzg4844.Point
	blobBytes []byte
}

// newDABatchV6 is a constructor for daBatchV6 that calls blobDataProofForPICircuit internally.
func newDABatchV6(version CodecVersion, batchIndex uint64, parentBatchHash, blobVersionedHash common.Hash, blob *kzg4844.Blob, z *kzg4844.Point, blobBytes []byte) (*daBatchV6, error) {
	daBatch := &daBatchV6{
		version:           version,
		batchIndex:        batchIndex,
		parentBatchHash:   parentBatchHash,
		blobVersionedHash: blobVersionedHash,
		blob:              blob,
		z:                 z,
		blobBytes:         blobBytes,
	}

	return daBatch, nil
}

func decodeDABatchV6(data []byte) (*daBatchV6, error) {
	if len(data) != daBatchV6EncodedLength {
		return nil, fmt.Errorf("invalid data length for DABatchV6, expected %d bytes but got %d", daBatchV6EncodedLength, len(data))
	}

	version := CodecVersion(data[daBatchOffsetVersion])
	batchIndex := binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV6OffsetBlobVersionedHash])
	blobVersionedHash := common.BytesToHash(data[daBatchV6OffsetBlobVersionedHash:daBatchV6OffsetParentBatchHash])
	parentBatchHash := common.BytesToHash(data[daBatchV6OffsetParentBatchHash:daBatchV6EncodedLength])

	return newDABatchV6(version, batchIndex, parentBatchHash, blobVersionedHash, nil, nil, nil)
}

// Encode serializes the DABatchV3 into bytes.
func (b *daBatchV6) Encode() []byte {
	batchBytes := make([]byte, daBatchV6EncodedLength)
	batchBytes[daBatchOffsetVersion] = byte(b.version)
	binary.BigEndian.PutUint64(batchBytes[daBatchOffsetBatchIndex:daBatchV6OffsetBlobVersionedHash], b.batchIndex)
	copy(batchBytes[daBatchV6OffsetBlobVersionedHash:daBatchV6OffsetParentBatchHash], b.blobVersionedHash[:])
	copy(batchBytes[daBatchV6OffsetParentBatchHash:daBatchV6EncodedLength], b.parentBatchHash[:])
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *daBatchV6) Hash() common.Hash {
	return crypto.Keccak256Hash(b.Encode())
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *daBatchV6) BlobDataProofForPointEvaluation() ([]byte, error) {
	if b.blob == nil {
		return nil, errors.New("called BlobDataProofForPointEvaluation with empty blob")
	}
	if b.z == nil {
		return nil, errors.New("called BlobDataProofForPointEvaluation with empty z")
	}

	commitment, err := kzg4844.BlobToCommitment(b.blob)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob commitment: %w", err)
	}

	proof, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return nil, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	return blobDataProofFromValues(*b.z, y, commitment, proof), nil
}

// Blob returns the blob of the batch.
func (b *daBatchV6) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *daBatchV6) BlobBytes() []byte {
	return b.blobBytes
}

// MarshalJSON implements the custom JSON serialization for daBatchV3.
// This method is designed to provide prover with batch info in snake_case format.
func (b *daBatchV6) MarshalJSON() ([]byte, error) {
	type daBatchV6JSON struct {
		Version           CodecVersion `json:"version"`
		BatchIndex        uint64       `json:"batch_index"`
		BlobVersionedHash string       `json:"blob_versioned_hash"`
		ParentBatchHash   string       `json:"parent_batch_hash"`
	}

	return json.Marshal(&daBatchV6JSON{
		Version:           b.version,
		BatchIndex:        b.batchIndex,
		BlobVersionedHash: b.blobVersionedHash.Hex(),
		ParentBatchHash:   b.parentBatchHash.Hex(),
	})
}

// Version returns the version of the DABatch.
func (b *daBatchV6) Version() CodecVersion {
	return b.version
}

// SkippedL1MessageBitmap returns the skipped L1 message bitmap of the DABatch.
// For daBatchV6, there is no skipped L1 message bitmap.
func (b *daBatchV6) SkippedL1MessageBitmap() []byte {
	return nil
}

// DataHash returns the data hash of the DABatch.
// For daBatchV6, there is no data hash.
func (b *daBatchV6) DataHash() common.Hash {
	return common.Hash{}
}
