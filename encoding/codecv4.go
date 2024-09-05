package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sync/atomic"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

type DACodecV4 struct {
	enableCompress uint32
}

// Codecv4MaxNumChunks is the maximum number of chunks that a batch can contain.
const Codecv4MaxNumChunks = 45

// Version returns the codec version.
func (o *DACodecV4) Version() CodecVersion {
	return CodecV4
}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (o *DACodecV4) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (DABlock, error) {
	return (&DACodecV3{}).NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (o *DACodecV4) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	return (&DACodecV3{}).NewDAChunk(chunk, totalL1MessagePoppedBefore)
}

// NewDABatch creates a DABatch from the provided Batch.
func (o *DACodecV4) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > Codecv4MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	if len(batch.Chunks[len(batch.Chunks)-1].Blocks) == 0 {
		return nil, errors.New("too few blocks in last chunk of the batch")
	}

	// batch data hash
	dataHash, err := o.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, blobBytes, err := o.constructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	lastChunk := batch.Chunks[len(batch.Chunks)-1]
	lastBlock := lastChunk.Blocks[len(lastChunk.Blocks)-1]

	daBatch := DABatchV4{
		DABatchV0: DABatchV0{
			Version:                uint8(CodecV4),
			BatchIndex:             batch.Index,
			L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
			TotalL1MessagePopped:   totalL1MessagePoppedAfter,
			DataHash:               dataHash,
			ParentBatchHash:        batch.ParentBatchHash,
			SkippedL1MessageBitmap: bitmapBytes,
		},
		BlobVersionedHash:  blobVersionedHash,
		LastBlockTimestamp: lastBlock.Header.Time,
		blob:               blob,
		z:                  z,
		blobBytes:          blobBytes,
	}

	daBatch.BlobDataProof, err = daBatch.blobDataProofForPICircuit()
	if err != nil {
		return nil, err
	}

	return &daBatch, nil
}

// NewDABatchWithExpectedBlobVersionedHashes creates a DABatch from the provided Batch.
// It also checks if the blob versioned hashes are as expected.
func (o *DACodecV4) NewDABatchWithExpectedBlobVersionedHashes(batch *Batch, hashes []common.Hash) (DABatch, error) {
	o.SetCompression(true)
	daBatch, err := o.NewDABatch(batch)
	if err != nil || !reflect.DeepEqual(daBatch.BlobVersionedHashes(), hashes) {
		o.SetCompression(false)
		daBatch, err = o.NewDABatch(batch)
		if err != nil {
			return nil, err
		}
	}

	if !reflect.DeepEqual(daBatch.BlobVersionedHashes(), hashes) {
		return nil, fmt.Errorf("blob versioned hashes do not match. Expected: %v, Got: %v", hashes, daBatch.BlobVersionedHashes())
	}

	return daBatch, nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (o *DACodecV4) constructBlobPayload(chunks []*Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + Codecv4MaxNumChunks*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+Codecv4MaxNumChunks+1)*32)

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
				rlpTxData, err := ConvertTxDataToRLPEncoding(tx, useMockTxData)
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

	// if we have fewer than Codecv4MaxNumChunks chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < Codecv4MaxNumChunks; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(batchBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	var blobBytes []byte
	if o.isCompressEnabled() {
		// blobBytes represents the compressed blob payload (batchBytes)
		var err error
		blobBytes, err = zstd.CompressScrollBatchBytes(batchBytes)
		if err != nil {
			return nil, common.Hash{}, nil, nil, err
		}
		if !useMockTxData {
			// Check compressed data compatibility.
			if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
				log.Error("constructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
				return nil, common.Hash{}, nil, nil, err
			}
		}
		blobBytes = append([]byte{1}, blobBytes...)
	} else {
		blobBytes = append([]byte{0}, batchBytes...)
	}

	if len(blobBytes) > 126976 {
		log.Error("constructBlobPayload: Blob payload exceeds maximum size", "size", len(blobBytes), "blobBytes", hex.EncodeToString(blobBytes))
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
	copy(challengePreimage[(1+Codecv4MaxNumChunks)*32:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), BLSModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	start := 32 - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, blobBytes, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (o *DACodecV4) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) != 193 {
		return nil, fmt.Errorf("invalid data length for DABatch, expected 193 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV4 {
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV4)
	}

	b := &DABatchV4{
		DABatchV0: DABatchV0{
			Version:              data[0],
			BatchIndex:           binary.BigEndian.Uint64(data[1:9]),
			L1MessagePopped:      binary.BigEndian.Uint64(data[9:17]),
			TotalL1MessagePopped: binary.BigEndian.Uint64(data[17:25]),
			DataHash:             common.BytesToHash(data[25:57]),
			ParentBatchHash:      common.BytesToHash(data[89:121]),
		},
		BlobVersionedHash:  common.BytesToHash(data[57:89]),
		LastBlockTimestamp: binary.BigEndian.Uint64(data[121:129]),
		BlobDataProof: [2]common.Hash{
			common.BytesToHash(data[129:161]),
			common.BytesToHash(data[161:193]),
		},
	}

	return b, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (o *DACodecV4) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	batchBytes, err := ConstructBatchPayloadInBlob([]*Chunk{c}, Codecv4MaxNumChunks)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	if o.isCompressEnabled() {
		blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
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
func (o *DACodecV4) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	batchBytes, err := ConstructBatchPayloadInBlob(b.Chunks, Codecv4MaxNumChunks)
	if err != nil {
		return 0, 0, err
	}
	var blobBytesLength uint64
	if o.isCompressEnabled() {
		blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
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
func (o *DACodecV4) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	batchBytes, err := ConstructBatchPayloadInBlob([]*Chunk{c}, Codecv4MaxNumChunks)
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
func (o *DACodecV4) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	batchBytes, err := ConstructBatchPayloadInBlob(b.Chunks, Codecv4MaxNumChunks)
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

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (o *DACodecV4) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return (&DACodecV3{}).EstimateChunkL1CommitCalldataSize(c)
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (o *DACodecV4) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	return (&DACodecV3{}).EstimateBatchL1CommitCalldataSize(b)
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (o *DACodecV4) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	return (&DACodecV3{}).EstimateChunkL1CommitGas(c)
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (o *DACodecV4) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	return (&DACodecV3{}).EstimateBatchL1CommitGas(b)
}

// isCompressEnabled checks if compression is enabled.
func (o *DACodecV4) isCompressEnabled() bool {
	return atomic.LoadUint32(&o.enableCompress) == 1
}

// SetCompression enables or disables compression.
func (o *DACodecV4) SetCompression(enable bool) {
	if enable {
		atomic.StoreUint32(&o.enableCompress, 1)
	} else {
		atomic.StoreUint32(&o.enableCompress, 0)
	}
}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func (o *DACodecV4) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	return (&DACodecV3{}).computeBatchDataHash(chunks, totalL1MessagePoppedBefore)
}

// DecodeDAChunks takes a byte slice and decodes it into a []DAChunk
func (o *DACodecV4) DecodeDAChunks(bytes [][]byte) ([]DAChunk, error) {
	return (&DACodecV3{}).DecodeDAChunks(bytes)
}
