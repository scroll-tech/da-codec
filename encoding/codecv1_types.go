package encoding

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// daChunkV1 groups consecutive DABlocks with their transactions.
type daChunkV1 daChunkV0

// newDAChunkV1 is a constructor for daChunkV1, initializing with blocks and transactions.
func newDAChunkV1(blocks []DABlock, transactions [][]*types.TransactionData) *daChunkV1 {
	return &daChunkV1{
		blocks:       blocks,
		transactions: transactions,
	}
}

// Encode serializes the DAChunk into a slice of bytes.
func (c *daChunkV1) Encode() ([]byte, error) {
	var chunkBytes []byte
	chunkBytes = append(chunkBytes, byte(len(c.blocks)))

	for _, block := range c.blocks {
		blockBytes := block.Encode()
		chunkBytes = append(chunkBytes, blockBytes...)
	}

	return chunkBytes, nil
}

// Hash computes the hash of the DAChunk data.
func (c *daChunkV1) Hash() (common.Hash, error) {
	var dataBytes []byte

	// concatenate block contexts
	for _, block := range c.blocks {
		encodedBlock := block.Encode()
		// only the first 58 bytes are used in the hashing process
		dataBytes = append(dataBytes, encodedBlock[:58]...)
	}

	// concatenate l1 tx hashes
	for _, blockTxs := range c.transactions {
		for _, txData := range blockTxs {
			if txData.Type != types.L1MessageTxType {
				continue
			}

			txHash := strings.TrimPrefix(txData.TxHash, "0x")
			hashBytes, err := hex.DecodeString(txHash)
			if err != nil {
				return common.Hash{}, err
			}
			if len(hashBytes) != 32 {
				return common.Hash{}, fmt.Errorf("unexpected hash: %s", txData.TxHash)
			}
			dataBytes = append(dataBytes, hashBytes...)
		}
	}

	hash := crypto.Keccak256Hash(dataBytes)
	return hash, nil
}

// BlockRange returns the block range of the DAChunk.
func (c *daChunkV1) BlockRange() (uint64, uint64, error) {
	if len(c.blocks) == 0 {
		return 0, 0, errors.New("number of blocks is 0")
	}

	return c.blocks[0].Number(), c.blocks[len(c.blocks)-1].Number(), nil
}

// daBatchV1 contains metadata about a batch of DAChunks.
type daBatchV1 struct {
	daBatchV0

	blobVersionedHash common.Hash
	blob              *kzg4844.Blob
	z                 *kzg4844.Point
}

// newDABatchV1 is a constructor for daBatchV1.
func newDABatchV1(version uint8, batchIndex, l1MessagePopped, totalL1MessagePopped uint64, dataHash, parentBatchHash, blobVersionedHash common.Hash, skippedL1MessageBitmap []byte, blob *kzg4844.Blob, z *kzg4844.Point) *daBatchV1 {
	return &daBatchV1{
		daBatchV0: daBatchV0{
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
func (b *daBatchV1) Encode() []byte {
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
func (b *daBatchV1) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// BlobDataProof computes the abi-encoded blob verification data.
func (b *daBatchV1) BlobDataProof() ([]byte, error) {
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

	return blobDataProofFromValues(*b.z, y, commitment, proof), nil
}

// Blob returns the blob of the batch.
func (b *daBatchV1) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *daBatchV1) BlobBytes() []byte {
	return nil
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
func (b *daBatchV1) BlobDataProofForPointEvaluation() ([]byte, error) {
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

// Version returns the version of the DABatch.
func (b *daBatchV1) Version() uint8 {
	return b.version
}

// SkippedL1MessageBitmap returns the skipped L1 message bitmap of the DABatch.
func (b *daBatchV1) SkippedL1MessageBitmap() []byte {
	return b.skippedL1MessageBitmap
}

// DataHash returns the data hash of the DABatch.
func (b *daBatchV1) DataHash() common.Hash {
	return b.dataHash
}
