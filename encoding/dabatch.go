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

// DABatchV0 contains metadata about a batch of DAChunks.
type DABatchV0 struct {
	version                uint8
	batchIndex             uint64
	l1MessagePopped        uint64
	totalL1MessagePopped   uint64
	dataHash               common.Hash
	parentBatchHash        common.Hash
	skippedL1MessageBitmap []byte
}

// NewDABatchV0 is a constructor for DABatchV0.
func NewDABatchV0(version uint8, batchIndex, l1MessagePopped, totalL1MessagePopped uint64, dataHash, parentBatchHash common.Hash, skippedL1MessageBitmap []byte) *DABatchV0 {
	return &DABatchV0{
		version:                version,
		batchIndex:             batchIndex,
		l1MessagePopped:        l1MessagePopped,
		totalL1MessagePopped:   totalL1MessagePopped,
		dataHash:               dataHash,
		parentBatchHash:        parentBatchHash,
		skippedL1MessageBitmap: skippedL1MessageBitmap,
	}
}

// Encode serializes the DABatch into bytes.
func (b *DABatchV0) Encode() []byte {
	batchBytes := make([]byte, 89+len(b.skippedL1MessageBitmap))
	batchBytes[0] = b.version
	binary.BigEndian.PutUint64(batchBytes[1:], b.batchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:], b.l1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:], b.totalL1MessagePopped)
	copy(batchBytes[25:], b.dataHash[:])
	copy(batchBytes[57:], b.parentBatchHash[:])
	copy(batchBytes[89:], b.skippedL1MessageBitmap[:])
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *DABatchV0) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// Blob returns the blob of the batch.
func (b *DABatchV0) Blob() *kzg4844.Blob {
	return nil
}

// BlobVersionedHashes returns the blob versioned hashes of the batch.
func (b *DABatchV0) BlobVersionedHashes() []common.Hash {
	return nil
}

// BlobBytes returns the blob bytes of the batch.
func (b *DABatchV0) BlobBytes() []byte {
	return nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *DABatchV0) BlobDataProofForPointEvaluation() ([]byte, error) {
	return nil, nil
}

// DABatchV1 contains metadata about a batch of DAChunks.
type DABatchV1 struct {
	DABatchV0

	blobVersionedHash common.Hash
	blob              *kzg4844.Blob
	z                 *kzg4844.Point
}

// NewDABatchV1 is a constructor for DABatchV1.
func NewDABatchV1(version uint8, batchIndex, l1MessagePopped, totalL1MessagePopped uint64, dataHash, parentBatchHash, blobVersionedHash common.Hash, skippedL1MessageBitmap []byte, blob *kzg4844.Blob, z *kzg4844.Point) *DABatchV1 {
	return &DABatchV1{
		DABatchV0: DABatchV0{
			version:                version,
			batchIndex:             batchIndex,
			l1MessagePopped:        l1MessagePopped,
			totalL1MessagePopped:   totalL1MessagePopped,
			dataHash:               dataHash,
			parentBatchHash:        parentBatchHash,
			skippedL1MessageBitmap: skippedL1MessageBitmap,
		},
		blobVersionedHash: blobVersionedHash,
		blob:              blob,
		z:                 z,
	}
}

// Encode serializes the DABatch into bytes.
func (b *DABatchV1) Encode() []byte {
	batchBytes := make([]byte, 121+len(b.skippedL1MessageBitmap))
	batchBytes[0] = b.version
	binary.BigEndian.PutUint64(batchBytes[1:], b.batchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:], b.l1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:], b.totalL1MessagePopped)
	copy(batchBytes[25:], b.dataHash[:])
	copy(batchBytes[57:], b.blobVersionedHash[:])
	copy(batchBytes[89:], b.parentBatchHash[:])
	copy(batchBytes[121:], b.skippedL1MessageBitmap[:])
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *DABatchV1) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// BlobDataProof computes the abi-encoded blob verification data.
func (b *DABatchV1) BlobDataProof() ([]byte, error) {
	if b.blob == nil {
		return nil, errors.New("called BlobDataProof with empty blob")
	}
	if b.z == nil {
		return nil, errors.New("called BlobDataProof with empty z")
	}

	commitment, err := kzg4844.BlobToCommitment(b.blob)
	if err != nil {
		return nil, errors.New("failed to create blob commitment")
	}

	proof, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return nil, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	return BlobDataProofFromValues(*b.z, y, commitment, proof), nil
}

// Blob returns the blob of the batch.
func (b *DABatchV1) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobVersionedHashes returns the blob versioned hashes of the batch.
func (b *DABatchV1) BlobVersionedHashes() []common.Hash {
	return []common.Hash{b.blobVersionedHash}
}

// BlobBytes returns the blob bytes of the batch.
func (b *DABatchV1) BlobBytes() []byte {
	return nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *DABatchV1) BlobDataProofForPointEvaluation() ([]byte, error) {
	return nil, nil
}

// DABatchV2 contains metadata about a batch of DAChunks.
type DABatchV2 struct {
	DABatchV0

	blobVersionedHash  common.Hash
	lastBlockTimestamp uint64
	blobDataProof      [2]common.Hash
	blob               *kzg4844.Blob
	z                  *kzg4844.Point
	blobBytes          []byte
}

// NewDABatchV2 is a constructor for DABatchV2 that calls blobDataProofForPICircuit internally.
func NewDABatchV2(version uint8,
	batchIndex, l1MessagePopped, totalL1MessagePopped, lastBlockTimestamp uint64,
	dataHash, parentBatchHash, blobVersionedHash common.Hash,
	skippedL1MessageBitmap []byte,
	blob *kzg4844.Blob, z *kzg4844.Point, blobBytes []byte,
) (*DABatchV2, error) {
	daBatch := &DABatchV2{
		DABatchV0: DABatchV0{
			version:                version,
			batchIndex:             batchIndex,
			l1MessagePopped:        l1MessagePopped,
			totalL1MessagePopped:   totalL1MessagePopped,
			dataHash:               dataHash,
			parentBatchHash:        parentBatchHash,
			skippedL1MessageBitmap: skippedL1MessageBitmap,
		},
		blobVersionedHash:  blobVersionedHash,
		lastBlockTimestamp: lastBlockTimestamp,
		blob:               blob,
		z:                  z,
		blobBytes:          blobBytes,
	}

	proof, err := daBatch.blobDataProofForPICircuit()
	if err != nil {
		return nil, err
	}

	daBatch.blobDataProof = proof

	return daBatch, nil
}

// NewDABatchV2WithProof is a constructor for DABatchV2 that allows directly passing blobDataProof.
func NewDABatchV2WithProof(version uint8,
	batchIndex, l1MessagePopped, totalL1MessagePopped, lastBlockTimestamp uint64,
	dataHash, parentBatchHash, blobVersionedHash common.Hash,
	skippedL1MessageBitmap []byte,
	blob *kzg4844.Blob, z *kzg4844.Point, blobBytes []byte,
	blobDataProof [2]common.Hash, // Accept blobDataProof directly
) *DABatchV2 {
	return &DABatchV2{
		DABatchV0: DABatchV0{
			version:                version,
			batchIndex:             batchIndex,
			l1MessagePopped:        l1MessagePopped,
			totalL1MessagePopped:   totalL1MessagePopped,
			dataHash:               dataHash,
			parentBatchHash:        parentBatchHash,
			skippedL1MessageBitmap: skippedL1MessageBitmap,
		},
		blobVersionedHash:  blobVersionedHash,
		lastBlockTimestamp: lastBlockTimestamp,
		blob:               blob,
		z:                  z,
		blobBytes:          blobBytes,
		blobDataProof:      blobDataProof, // Set blobDataProof directly
	}
}

// Encode serializes the DABatch into bytes.
func (b *DABatchV2) Encode() []byte {
	batchBytes := make([]byte, 193)
	batchBytes[0] = b.version
	binary.BigEndian.PutUint64(batchBytes[1:9], b.batchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:17], b.l1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:25], b.totalL1MessagePopped)
	copy(batchBytes[25:57], b.dataHash[:])
	copy(batchBytes[57:89], b.blobVersionedHash[:])
	copy(batchBytes[89:121], b.parentBatchHash[:])
	binary.BigEndian.PutUint64(batchBytes[121:129], b.lastBlockTimestamp)
	copy(batchBytes[129:161], b.blobDataProof[0].Bytes())
	copy(batchBytes[161:193], b.blobDataProof[1].Bytes())
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *DABatchV2) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// blobDataProofForPICircuit computes the abi-encoded blob verification data.
func (b *DABatchV2) blobDataProofForPICircuit() ([2]common.Hash, error) {
	if b.blob == nil {
		return [2]common.Hash{}, errors.New("called blobDataProofForPICircuit with empty blob")
	}
	if b.z == nil {
		return [2]common.Hash{}, errors.New("called blobDataProofForPICircuit with empty z")
	}

	_, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return [2]common.Hash{}, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	// Memory layout of result:
	// | z       | y       |
	// |---------|---------|
	// | bytes32 | bytes32 |
	var result [2]common.Hash
	result[0] = common.BytesToHash(b.z[:])
	result[1] = common.BytesToHash(y[:])

	return result, nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *DABatchV2) BlobDataProofForPointEvaluation() ([]byte, error) {
	if b.blob == nil {
		return nil, errors.New("called BlobDataProofForPointEvaluation with empty blob")
	}
	if b.z == nil {
		return nil, errors.New("called BlobDataProofForPointEvaluation with empty z")
	}

	commitment, err := kzg4844.BlobToCommitment(b.blob)
	if err != nil {
		return nil, errors.New("failed to create blob commitment")
	}

	proof, y, err := kzg4844.ComputeProof(b.blob, *b.z)
	if err != nil {
		return nil, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(b.z[:]))
	}

	return BlobDataProofFromValues(*b.z, y, commitment, proof), nil
}

// Blob returns the blob of the batch.
func (b *DABatchV2) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobVersionedHashes returns the blob versioned hashes of the batch.
func (b *DABatchV2) BlobVersionedHashes() []common.Hash {
	return []common.Hash{b.blobVersionedHash}
}

// BlobBytes returns the blob bytes of the batch.
func (b *DABatchV2) BlobBytes() []byte {
	return b.blobBytes
}

// MarshalJSON implements the custom JSON serialization for DABatchV2.
// This method is designed to provide prover with batch info in snake_case format.
func (b *DABatchV2) MarshalJSON() ([]byte, error) {
	type daBatchV2JSON struct {
		Version                uint8     `json:"version"`
		BatchIndex             uint64    `json:"batch_index"`
		L1MessagePopped        uint64    `json:"l1_message_popped"`
		TotalL1MessagePopped   uint64    `json:"total_l1_message_popped"`
		DataHash               string    `json:"data_hash"`
		ParentBatchHash        string    `json:"parent_batch_hash"`
		SkippedL1MessageBitmap string    `json:"skipped_l1_message_bitmap"`
		BlobVersionedHash      string    `json:"blob_versioned_hash"`
		LastBlockTimestamp     uint64    `json:"last_block_timestamp"`
		BlobBytes              string    `json:"blob_bytes"`
		BlobDataProof          [2]string `json:"blob_data_proof"`
	}

	return json.Marshal(&daBatchV2JSON{
		Version:                b.version,
		BatchIndex:             b.batchIndex,
		L1MessagePopped:        b.l1MessagePopped,
		TotalL1MessagePopped:   b.totalL1MessagePopped,
		DataHash:               b.dataHash.Hex(),
		ParentBatchHash:        b.parentBatchHash.Hex(),
		SkippedL1MessageBitmap: common.Bytes2Hex(b.skippedL1MessageBitmap),
		BlobVersionedHash:      b.blobVersionedHash.Hex(),
		LastBlockTimestamp:     b.lastBlockTimestamp,
		BlobBytes:              common.Bytes2Hex(b.blobBytes),
		BlobDataProof: [2]string{
			b.blobDataProof[0].Hex(),
			b.blobDataProof[1].Hex(),
		},
	})
}
