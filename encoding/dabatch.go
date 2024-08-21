package encoding

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// DABatch contains metadata about a batch of DAChunks.
type DABatchV0 struct {
	Version                uint8
	BatchIndex             uint64
	L1MessagePopped        uint64
	TotalL1MessagePopped   uint64
	DataHash               common.Hash
	ParentBatchHash        common.Hash
	SkippedL1MessageBitmap []byte
}

// Encode serializes the DABatch into bytes.
func (b *DABatchV0) Encode() []byte {
	batchBytes := make([]byte, 89+len(b.SkippedL1MessageBitmap))
	batchBytes[0] = b.Version
	binary.BigEndian.PutUint64(batchBytes[1:], b.BatchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:], b.L1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:], b.TotalL1MessagePopped)
	copy(batchBytes[25:], b.DataHash[:])
	copy(batchBytes[57:], b.ParentBatchHash[:])
	copy(batchBytes[89:], b.SkippedL1MessageBitmap[:])
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
	// header
	Version                uint8
	BatchIndex             uint64
	L1MessagePopped        uint64
	TotalL1MessagePopped   uint64
	DataHash               common.Hash
	BlobVersionedHash      common.Hash
	ParentBatchHash        common.Hash
	SkippedL1MessageBitmap []byte

	// blob payload
	blob *kzg4844.Blob
	z    *kzg4844.Point
}

// Encode serializes the DABatch into bytes.
func (b *DABatchV1) Encode() []byte {
	batchBytes := make([]byte, 121+len(b.SkippedL1MessageBitmap))
	batchBytes[0] = b.Version
	binary.BigEndian.PutUint64(batchBytes[1:], b.BatchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:], b.L1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:], b.TotalL1MessagePopped)
	copy(batchBytes[25:], b.DataHash[:])
	copy(batchBytes[57:], b.BlobVersionedHash[:])
	copy(batchBytes[89:], b.ParentBatchHash[:])
	copy(batchBytes[121:], b.SkippedL1MessageBitmap[:])
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

	// Memory layout of ``_blobDataProof``:
	// | z       | y       | kzg_commitment | kzg_proof |
	// |---------|---------|----------------|-----------|
	// | bytes32 | bytes32 | bytes48        | bytes48   |

	values := []interface{}{*b.z, y, commitment, proof}
	blobDataProofArgs, err := GetBlobDataProofArgs()
	if err != nil {
		return nil, fmt.Errorf("failed to get blob data proof args, err: %w", err)
	}
	return blobDataProofArgs.Pack(values...)
}

// Blob returns the blob of the batch.
func (b *DABatchV1) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *DABatchV1) BlobBytes() []byte {
	return nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *DABatchV1) BlobDataProofForPointEvaluation() ([]byte, error) {
	return nil, nil
}

type DABatchV2 = DABatchV1

// DABatchV3 contains metadata about a batch of DAChunks.
type DABatchV3 struct {
	// header
	Version              uint8          `json:"version"`
	BatchIndex           uint64         `json:"batch_index"`
	L1MessagePopped      uint64         `json:"l1_message_popped"`
	TotalL1MessagePopped uint64         `json:"total_l1_message_popped"`
	DataHash             common.Hash    `json:"data_hash"`
	BlobVersionedHash    common.Hash    `json:"blob_versioned_hash"`
	ParentBatchHash      common.Hash    `json:"parent_batch_hash"`
	LastBlockTimestamp   uint64         `json:"last_block_timestamp"`
	BlobDataProof        [2]common.Hash `json:"blob_data_proof"`

	// blob payload
	blob *kzg4844.Blob
	z    *kzg4844.Point

	// for batch task
	blobBytes []byte
}

// Encode serializes the DABatch into bytes.
func (b *DABatchV3) Encode() []byte {
	batchBytes := make([]byte, 193)
	batchBytes[0] = b.Version
	binary.BigEndian.PutUint64(batchBytes[1:9], b.BatchIndex)
	binary.BigEndian.PutUint64(batchBytes[9:17], b.L1MessagePopped)
	binary.BigEndian.PutUint64(batchBytes[17:25], b.TotalL1MessagePopped)
	copy(batchBytes[25:57], b.DataHash[:])
	copy(batchBytes[57:89], b.BlobVersionedHash[:])
	copy(batchBytes[89:121], b.ParentBatchHash[:])
	binary.BigEndian.PutUint64(batchBytes[121:129], b.LastBlockTimestamp)
	copy(batchBytes[129:161], b.BlobDataProof[0].Bytes())
	copy(batchBytes[161:193], b.BlobDataProof[1].Bytes())
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *DABatchV3) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// blobDataProofForPICircuit computes the abi-encoded blob verification data.
func (b *DABatchV3) blobDataProofForPICircuit() ([2]common.Hash, error) {
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
func (b *DABatchV3) BlobDataProofForPointEvaluation() ([]byte, error) {
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

	// Memory layout of ``_blobDataProof``:
	// | z       | y       | kzg_commitment | kzg_proof |
	// |---------|---------|----------------|-----------|
	// | bytes32 | bytes32 | bytes48        | bytes48   |

	values := []interface{}{*b.z, y, commitment, proof}
	blobDataProofArgs, err := GetBlobDataProofArgs()
	if err != nil {
		return nil, fmt.Errorf("failed to get blob data proof args, err: %w", err)
	}
	return blobDataProofArgs.Pack(values...)
}

// Blob returns the blob of the batch.
func (b *DABatchV3) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *DABatchV3) BlobBytes() []byte {
	return b.blobBytes
}

type DABatchV4 = DABatchV3
