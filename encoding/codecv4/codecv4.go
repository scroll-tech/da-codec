package codecv4

/*
#include <stdint.h>
char* compress_scroll_batch_bytes(uint8_t* src, uint64_t src_size, uint8_t* output_buf, uint64_t *output_buf_size);
*/
import "C"

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/scroll-tech/go-ethereum/accounts/abi"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv1"
	"github.com/scroll-tech/da-codec/encoding/codecv3"
)

// MaxNumChunks is the maximum number of chunks that a batch can contain.
const MaxNumChunks = codecv3.MaxNumChunks

// DABlock represents a Data Availability Block.
type DABlock = codecv3.DABlock

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk = codecv3.DAChunk

// DABatch contains metadata about a batch of DAChunks.
type DABatch struct {
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

// NewDABlock creates a new DABlock from the given encoding.Block and the total number of L1 messages popped before.
func NewDABlock(block *encoding.Block, totalL1MessagePoppedBefore uint64) (*DABlock, error) {
	return codecv3.NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given encoding.Chunk and the total number of L1 messages popped before.
func NewDAChunk(chunk *encoding.Chunk, totalL1MessagePoppedBefore uint64) (*DAChunk, error) {
	return codecv3.NewDAChunk(chunk, totalL1MessagePoppedBefore)
}

// NewDABatch creates a DABatch from the provided encoding.Batch.
func NewDABatch(batch *encoding.Batch, enableEncode bool) (*DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, errors.New("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := ComputeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	_, totalL1MessagePoppedAfter, err := encoding.ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := ConstructBlobPayload(batch.Chunks, enableEncode, false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	daBatch := DABatch{
		Version:              uint8(encoding.CodecV4),
		BatchIndex:           batch.Index,
		L1MessagePopped:      totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
		TotalL1MessagePopped: totalL1MessagePoppedAfter,
		DataHash:             dataHash,
		BlobVersionedHash:    blobVersionedHash,
		ParentBatchHash:      batch.ParentBatchHash,
		LastBlockTimestamp:   lastBlock.Header.Time,
		blob:                 blob,
		z:                    z,
		blobBytes:            blobBytes,
	}

	daBatch.BlobDataProof, err = daBatch.blobDataProofForPICircuit()
	if err != nil {
		return nil, err
	}

	return &daBatch, nil
}

// ComputeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func ComputeBatchDataHash(chunks []*encoding.Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	return codecv3.ComputeBatchDataHash(chunks, totalL1MessagePoppedBefore)
}

// ConstructBlobPayload constructs the 4844 blob payload.
func ConstructBlobPayload(chunks []*encoding.Chunk, enableEncode bool, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + MaxNumChunks*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+MaxNumChunks+1)*32)

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
				rlpTxData, err := encoding.ConvertTxDataToRLPEncoding(tx, useMockTxData)
				if err != nil {
					return nil, common.Hash{}, nil, nil, err
				}
				batchBytes = append(batchBytes, rlpTxData...)
			}
		}

		// blob metadata: chunki_size
		if chunkSize := len(batchBytes) - currentChunkStartIndex; chunkSize != 0 {
			binary.BigEndian.PutUint32(batchBytes[2+4*chunkID:], uint32(chunkSize))
		}

		// challenge: compute chunk data hash
		chunkDataHash = crypto.Keccak256Hash(batchBytes[currentChunkStartIndex:])
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// if we have fewer than MaxNumChunks chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < MaxNumChunks; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(batchBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	var blobBytes []byte
	if enableEncode {
		// blobBytes represents the compressed blob payload (batchBytes)
		var err error
		blobBytes, err = compressScrollBatchBytes(batchBytes)
		if err != nil {
			return nil, common.Hash{}, nil, nil, err
		}
		if !useMockTxData {
			// Check compressed data compatibility.
			if err = encoding.CheckCompressedDataCompatibility(blobBytes); err != nil {
				log.Error("ConstructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
				return nil, common.Hash{}, nil, nil, err
			}
		}
		blobBytes = append([]byte{1}, blobBytes...)
	} else {
		blobBytes = batchBytes
		blobBytes = append([]byte{0}, batchBytes...)
	}

	if len(blobBytes) > 126976 {
		log.Error("ConstructBlobPayload: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return nil, common.Hash{}, nil, nil, errors.New("Blob payload exceeds maximum size")
	}

	// convert raw data to BLSFieldElements
	blob, err := MakeBlobCanonical(blobBytes)
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
	copy(challengePreimage[(1+MaxNumChunks)*32:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), encoding.BLSModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	start := 32 - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, blobBytes, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func NewDABatchFromBytes(data []byte) (*DABatch, error) {
	if len(data) != 193 {
		return nil, fmt.Errorf("invalid data length for DABatch, expected 193 bytes but got %d", len(data))
	}

	b := &DABatch{
		Version:              data[0],
		BatchIndex:           binary.BigEndian.Uint64(data[1:9]),
		L1MessagePopped:      binary.BigEndian.Uint64(data[9:17]),
		TotalL1MessagePopped: binary.BigEndian.Uint64(data[17:25]),
		DataHash:             common.BytesToHash(data[25:57]),
		BlobVersionedHash:    common.BytesToHash(data[57:89]),
		ParentBatchHash:      common.BytesToHash(data[89:121]),
		LastBlockTimestamp:   binary.BigEndian.Uint64(data[121:129]),
		BlobDataProof: [2]common.Hash{
			common.BytesToHash(data[129:161]),
			common.BytesToHash(data[161:193]),
		},
	}

	return b, nil
}

// Encode serializes the DABatch into bytes.
func (b *DABatch) Encode() []byte {
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
func (b *DABatch) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// blobDataProofForPICircuit computes the abi-encoded blob verification data.
func (b *DABatch) blobDataProofForPICircuit() ([2]common.Hash, error) {
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
func (b *DABatch) BlobDataProofForPointEvaluation() ([]byte, error) {
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
func (b *DABatch) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *DABatch) BlobBytes() []byte {
	return b.blobBytes
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func EstimateChunkL1CommitBatchSizeAndBlobSize(c *encoding.Chunk, enableEncode bool) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayload([]*encoding.Chunk{c})
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	if enableEncode {
		blobBytes, err := compressScrollBatchBytes(batchBytes)
		if err != nil {
			return 0, 0, err
		}
		blobBytesLength = 1 + uint64(len(blobBytes))
	} else {
		blobBytesLength = 1 + uint64(len(batchBytes))
	}
	return uint64(len(batchBytes)), CalculatePaddedBlobSize(blobBytesLength), nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func EstimateBatchL1CommitBatchSizeAndBlobSize(b *encoding.Batch, enableEncode bool) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayload(b.Chunks)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	if enableEncode {
		blobBytes, err := compressScrollBatchBytes(batchBytes)
		if err != nil {
			return 0, 0, err
		}
		blobBytesLength = 1 + uint64(len(blobBytes))
	} else {
		blobBytesLength = 1 + uint64(len(batchBytes))
	}
	return uint64(len(batchBytes)), CalculatePaddedBlobSize(blobBytesLength), nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func CheckChunkCompressedDataCompatibility(c *encoding.Chunk) (bool, error) {
	batchBytes, err := constructBatchPayload([]*encoding.Chunk{c})
	if err != nil {
		return false, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	if err = encoding.CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckChunkCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func CheckBatchCompressedDataCompatibility(b *encoding.Batch) (bool, error) {
	batchBytes, err := constructBatchPayload(b.Chunks)
	if err != nil {
		return false, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	if err = encoding.CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckBatchCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func EstimateChunkL1CommitCalldataSize(c *encoding.Chunk) uint64 {
	return codecv3.EstimateChunkL1CommitCalldataSize(c)
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func EstimateBatchL1CommitCalldataSize(b *encoding.Batch) uint64 {
	return codecv3.EstimateBatchL1CommitCalldataSize(b)
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func EstimateChunkL1CommitGas(c *encoding.Chunk) uint64 {
	return codecv3.EstimateChunkL1CommitGas(c)
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func EstimateBatchL1CommitGas(b *encoding.Batch) uint64 {
	return codecv3.EstimateBatchL1CommitGas(b)
}

// GetBlobDataProofArgs gets the blob data proof arguments for batch commitment and returns error if initialization fails.
func GetBlobDataProofArgs() (*abi.Arguments, error) {
	return codecv3.GetBlobDataProofArgs()
}

// checkBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func checkBatchCompressedDataCompatibility(b *encoding.Batch) (bool, error) {
	batchBytes, err := constructBatchPayload(b.Chunks)
	if err != nil {
		return false, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	if err = encoding.CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckBatchCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// constructBatchPayload constructs the batch payload.
// This function is only used in compressed batch payload length estimation.
func constructBatchPayload(chunks []*encoding.Chunk) ([]byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + MaxNumChunks*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// batch metadata: num_chunks
	binary.BigEndian.PutUint16(batchBytes[0:], uint16(len(chunks)))

	// encode batch metadata and L2 transactions,
	for chunkID, chunk := range chunks {
		currentChunkStartIndex := len(batchBytes)

		for _, block := range chunk.Blocks {
			for _, tx := range block.Transactions {
				if tx.Type == types.L1MessageTxType {
					continue
				}

				// encode L2 txs into batch payload
				rlpTxData, err := encoding.ConvertTxDataToRLPEncoding(tx, false /* no mock */)
				if err != nil {
					return nil, err
				}
				batchBytes = append(batchBytes, rlpTxData...)
			}
		}

		// batch metadata: chunki_size
		if chunkSize := len(batchBytes) - currentChunkStartIndex; chunkSize != 0 {
			binary.BigEndian.PutUint32(batchBytes[2+4*chunkID:], uint32(chunkSize))
		}
	}
	return batchBytes, nil
}

// compressScrollBatchBytes compresses the given batch of bytes.
// The output buffer is allocated with an extra 128 bytes to accommodate metadata overhead or error message.
func compressScrollBatchBytes(batchBytes []byte) ([]byte, error) {
	srcSize := C.uint64_t(len(batchBytes))
	outbufSize := C.uint64_t(len(batchBytes) + 128) // Allocate output buffer with extra 128 bytes
	outbuf := make([]byte, outbufSize)

	if err := C.compress_scroll_batch_bytes((*C.uchar)(unsafe.Pointer(&batchBytes[0])), srcSize,
		(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outbufSize); err != nil {
		return nil, fmt.Errorf("failed to compress scroll batch bytes: %s", C.GoString(err))
	}

	return outbuf[:int(outbufSize)], nil
}

// MakeBlobCanonical converts the raw blob data into the canonical blob representation of 4096 BLSFieldElements.
func MakeBlobCanonical(blobBytes []byte) (*kzg4844.Blob, error) {
	return codecv1.MakeBlobCanonical(blobBytes)
}

// CalculatePaddedBlobSize calculates the required size on blob storage
// where every 32 bytes can store only 31 bytes of actual data, with the first byte being zero.
func CalculatePaddedBlobSize(dataSize uint64) uint64 {
	return codecv1.CalculatePaddedBlobSize(dataSize)
}
