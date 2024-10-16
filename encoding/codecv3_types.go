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
type daBatchV3 struct {
	daBatchV0

	blobVersionedHash  common.Hash
	lastBlockTimestamp uint64
	blobDataProof      [2]common.Hash
	blob               *kzg4844.Blob
	z                  *kzg4844.Point
	blobBytes          []byte
}

// newDABatchV3 is a constructor for daBatchV3 that calls blobDataProofForPICircuit internally.
func newDABatchV3(version uint8, batchIndex, l1MessagePopped, totalL1MessagePopped, lastBlockTimestamp uint64,
	dataHash, parentBatchHash, blobVersionedHash common.Hash, skippedL1MessageBitmap []byte, blob *kzg4844.Blob,
	z *kzg4844.Point, blobBytes []byte) (*daBatchV3, error) {
	daBatch := &daBatchV3{
		daBatchV0: daBatchV0{
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

// newDABatchV3WithProof is a constructor for daBatchV3 that allows directly passing blobDataProof.
func newDABatchV3WithProof(version uint8, batchIndex, l1MessagePopped, totalL1MessagePopped, lastBlockTimestamp uint64,
	dataHash, parentBatchHash, blobVersionedHash common.Hash, skippedL1MessageBitmap []byte,
	blob *kzg4844.Blob, z *kzg4844.Point, blobBytes []byte, blobDataProof [2]common.Hash) *daBatchV3 {
	return &daBatchV3{
		daBatchV0: daBatchV0{
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
func (b *daBatchV3) Encode() []byte {
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
func (b *daBatchV3) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// blobDataProofForPICircuit computes the abi-encoded blob verification data.
func (b *daBatchV3) blobDataProofForPICircuit() ([2]common.Hash, error) {
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
func (b *daBatchV3) BlobDataProofForPointEvaluation() ([]byte, error) {
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

	return blobDataProofFromValues(*b.z, y, commitment, proof), nil
}

// Blob returns the blob of the batch.
func (b *daBatchV3) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *daBatchV3) BlobBytes() []byte {
	return b.blobBytes
}

// MarshalJSON implements the custom JSON serialization for daBatchV3.
// This method is designed to provide prover with batch info in snake_case format.
func (b *daBatchV3) MarshalJSON() ([]byte, error) {
	type daBatchV3JSON struct {
		Version              uint8     `json:"version"`
		BatchIndex           uint64    `json:"batch_index"`
		L1MessagePopped      uint64    `json:"l1_message_popped"`
		TotalL1MessagePopped uint64    `json:"total_l1_message_popped"`
		DataHash             string    `json:"data_hash"`
		ParentBatchHash      string    `json:"parent_batch_hash"`
		BlobVersionedHash    string    `json:"blob_versioned_hash"`
		LastBlockTimestamp   uint64    `json:"last_block_timestamp"`
		BlobDataProof        [2]string `json:"blob_data_proof"`
	}

	return json.Marshal(&daBatchV3JSON{
		Version:              b.version,
		BatchIndex:           b.batchIndex,
		L1MessagePopped:      b.l1MessagePopped,
		TotalL1MessagePopped: b.totalL1MessagePopped,
		DataHash:             b.dataHash.Hex(),
		ParentBatchHash:      b.parentBatchHash.Hex(),
		BlobVersionedHash:    b.blobVersionedHash.Hex(),
		LastBlockTimestamp:   b.lastBlockTimestamp,
		BlobDataProof: [2]string{
			b.blobDataProof[0].Hex(),
			b.blobDataProof[1].Hex(),
		},
	})
}

// Version returns the version of the DABatch.
func (b *daBatchV3) Version() CodecVersion {
	return CodecVersion(b.version)
}

// SkippedL1MessageBitmap returns the skipped L1 message bitmap of the DABatch.
func (b *daBatchV3) SkippedL1MessageBitmap() []byte {
	return b.skippedL1MessageBitmap
}

// DataHash returns the data hash of the DABatch.
func (b *daBatchV3) DataHash() common.Hash {
	return b.dataHash
}
