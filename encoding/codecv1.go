package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

type DACodecV1 struct{}

// Codecv1MaxNumChunks is the maximum number of chunks that a batch can contain.
const Codecv1MaxNumChunks = 15

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (o *DACodecV1) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (*DABlock, error) {
	return (&DACodecV0{}).NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (o *DACodecV1) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > 255 {
		return nil, errors.New("number of blocks exceeds 1 byte")
	}

	var blocks []*DABlock
	var txs [][]*types.TransactionData

	for _, block := range chunk.Blocks {
		b, err := o.NewDABlock(block, totalL1MessagePoppedBefore)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
		totalL1MessagePoppedBefore += block.NumL1Messages(totalL1MessagePoppedBefore)
		txs = append(txs, block.Transactions)
	}

	daChunk := DAChunkV1{
		Blocks:       blocks,
		Transactions: txs,
	}

	return &daChunk, nil
}

// NewDABatch creates a DABatch from the provided Batch.
func (o *DACodecV1) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > Codecv1MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
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
	blob, blobVersionedHash, z, err := o.constructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	daBatch := DABatchV1{
		DABatchBase: DABatchBase{
			Version:                uint8(CodecV1),
			BatchIndex:             batch.Index,
			L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
			TotalL1MessagePopped:   totalL1MessagePoppedAfter,
			DataHash:               dataHash,
			ParentBatchHash:        batch.ParentBatchHash,
			SkippedL1MessageBitmap: bitmapBytes,
		},
		BlobVersionedHash: blobVersionedHash,
		blob:              blob,
		z:                 z,
	}

	return &daBatch, nil
}

// NewDABatchWithExpectedBlobVersionedHashes creates a DABatch from the provided Batch.
// It also checks if the blob versioned hashes are as expected.
func (o *DACodecV1) NewDABatchWithExpectedBlobVersionedHashes(batch *Batch, hashes []common.Hash) (DABatch, error) {
	daBatch, err := o.NewDABatch(batch)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(daBatch.BlobVersionedHashes(), hashes) {
		return nil, fmt.Errorf("blob versioned hashes do not match. Expected: %v, Got: %v", hashes, daBatch.BlobVersionedHashes())
	}

	return daBatch, nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (o *DACodecV1) constructBlobPayload(chunks []*Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + Codecv1MaxNumChunks*4

	// the raw (un-padded) blob payload
	blobBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+Codecv1MaxNumChunks+1)*32)

	// the chunk data hash used for calculating the challenge preimage
	var chunkDataHash common.Hash

	// blob metadata: num_chunks
	binary.BigEndian.PutUint16(blobBytes[0:], uint16(len(chunks)))

	// encode blob metadata and L2 transactions,
	// and simultaneously also build challenge preimage
	for chunkID, chunk := range chunks {
		currentChunkStartIndex := len(blobBytes)

		for _, block := range chunk.Blocks {
			for _, tx := range block.Transactions {
				if tx.Type == types.L1MessageTxType {
					continue
				}

				// encode L2 txs into blob payload
				rlpTxData, err := ConvertTxDataToRLPEncoding(tx, useMockTxData)
				if err != nil {
					return nil, common.Hash{}, nil, err
				}
				blobBytes = append(blobBytes, rlpTxData...)
			}
		}

		// blob metadata: chunki_size
		if chunkSize := len(blobBytes) - currentChunkStartIndex; chunkSize != 0 {
			binary.BigEndian.PutUint32(blobBytes[2+4*chunkID:], uint32(chunkSize))
		}

		// challenge: compute chunk data hash
		chunkDataHash = crypto.Keccak256Hash(blobBytes[currentChunkStartIndex:])
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// if we have fewer than Codecv1MaxNumChunks chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < Codecv1MaxNumChunks; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(blobBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	// convert raw data to BLSFieldElements
	blob, err := MakeBlobCanonical(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, err
	}

	// compute blob versioned hash
	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return nil, common.Hash{}, nil, errors.New("failed to create blob commitment")
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	// challenge: append blob versioned hash
	copy(challengePreimage[(1+Codecv1MaxNumChunks)*32:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), BLSModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	start := 32 - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (o *DACodecV1) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 121 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 121 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV1 {
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV1)
	}

	b := &DABatchV1{
		DABatchBase: DABatchBase{
			Version:                data[0],
			BatchIndex:             binary.BigEndian.Uint64(data[1:9]),
			L1MessagePopped:        binary.BigEndian.Uint64(data[9:17]),
			TotalL1MessagePopped:   binary.BigEndian.Uint64(data[17:25]),
			DataHash:               common.BytesToHash(data[25:57]),
			ParentBatchHash:        common.BytesToHash(data[89:121]),
			SkippedL1MessageBitmap: data[121:],
		},
		BlobVersionedHash: common.BytesToHash(data[57:89]),
	}

	return b, nil
}

// EstimateChunkL1CommitBlobSize estimates the size of the L1 commit blob for a single chunk.
func (o *DACodecV1) EstimateChunkL1CommitBlobSize(c *Chunk) (uint64, error) {
	metadataSize := uint64(2 + 4*Codecv1MaxNumChunks) // over-estimate: adding metadata length
	chunkDataSize, err := o.chunkL1CommitBlobDataSize(c)
	if err != nil {
		return 0, err
	}
	return CalculatePaddedBlobSize(metadataSize + chunkDataSize), nil
}

// EstimateBatchL1CommitBlobSize estimates the total size of the L1 commit blob for a batch.
func (o *DACodecV1) EstimateBatchL1CommitBlobSize(b *Batch) (uint64, error) {
	metadataSize := uint64(2 + 4*Codecv1MaxNumChunks)
	var batchDataSize uint64
	for _, c := range b.Chunks {
		chunkDataSize, err := o.chunkL1CommitBlobDataSize(c)
		if err != nil {
			return 0, err
		}
		batchDataSize += chunkDataSize
	}
	return CalculatePaddedBlobSize(metadataSize + batchDataSize), nil
}

func (o *DACodecV1) chunkL1CommitBlobDataSize(c *Chunk) (uint64, error) {
	var dataSize uint64
	for _, block := range c.Blocks {
		for _, tx := range block.Transactions {
			if tx.Type == types.L1MessageTxType {
				continue
			}

			rlpTxData, err := ConvertTxDataToRLPEncoding(tx, false /* no mock */)
			if err != nil {
				return 0, err
			}
			dataSize += uint64(len(rlpTxData))
		}
	}
	return dataSize, nil
}

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func (o *DACodecV1) EstimateBlockL1CommitGas(b *Block) (uint64, error) {
	var total uint64
	var numL1Messages uint64
	for _, txData := range b.Transactions {
		if txData.Type == types.L1MessageTxType {
			numL1Messages++
			continue
		}
	}

	total += CalldataNonZeroByteGas * BlockContextByteSize

	// sload
	total += 2100 * numL1Messages // numL1Messages times cold sload in L1MessageQueue

	// staticcall
	total += 100 * numL1Messages // numL1Messages times call to L1MessageQueue
	total += 100 * numL1Messages // numL1Messages times warm address access to L1MessageQueue

	total += GetMemoryExpansionCost(36) * numL1Messages // staticcall to proxy
	total += 100 * numL1Messages                        // read admin in proxy
	total += 100 * numL1Messages                        // read impl in proxy
	total += 100 * numL1Messages                        // access impl
	total += GetMemoryExpansionCost(36) * numL1Messages // delegatecall to impl

	return total, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (o *DACodecV1) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return uint64(BlockContextByteSize * len(c.Blocks)), nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (o *DACodecV1) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	var totalNonSkippedL1Messages uint64
	var totalL1CommitGas uint64
	for _, block := range c.Blocks {
		totalNonSkippedL1Messages += uint64(len(block.Transactions)) - block.NumL2Transactions()
		blockL1CommitGas, err := o.EstimateBlockL1CommitGas(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += blockL1CommitGas
	}

	numBlocks := uint64(len(c.Blocks))
	totalL1CommitGas += 100 * numBlocks        // numBlocks times warm sload
	totalL1CommitGas += CalldataNonZeroByteGas // numBlocks field of chunk encoding in calldata

	totalL1CommitGas += GetKeccak256Gas(58*numBlocks + 32*totalNonSkippedL1Messages) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (o *DACodecV1) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	var totalL1CommitGas uint64

	// Add extra gas costs
	totalL1CommitGas += 100000                 // constant to account for ops like _getAdmin, _implementation, _requireNotPaused, etc
	totalL1CommitGas += 4 * 2100               // 4 one-time cold sload for commitBatch
	totalL1CommitGas += 20000                  // 1 time sstore
	totalL1CommitGas += 21000                  // base fee for tx
	totalL1CommitGas += CalldataNonZeroByteGas // version in calldata

	// adjusting gas:
	// add 1 time cold sload (2100 gas) for L1MessageQueue
	// add 1 time cold address access (2600 gas) for L1MessageQueue
	// minus 1 time warm sload (100 gas) & 1 time warm address access (100 gas)
	totalL1CommitGas += (2100 + 2600 - 100 - 100)
	totalL1CommitGas += GetKeccak256Gas(89 + 32)           // parent batch header hash, length is estimated as 89 (constant part)+ 32 (1 skippedL1MessageBitmap)
	totalL1CommitGas += CalldataNonZeroByteGas * (89 + 32) // parent batch header in calldata

	// adjust batch data hash gas cost
	totalL1CommitGas += GetKeccak256Gas(uint64(32 * len(b.Chunks)))

	totalL1MessagePoppedBefore := b.TotalL1MessagePoppedBefore

	for _, chunk := range b.Chunks {
		chunkL1CommitGas, err := o.EstimateChunkL1CommitGas(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += chunkL1CommitGas

		totalL1MessagePoppedInChunk := chunk.NumL1Messages(totalL1MessagePoppedBefore)
		totalL1MessagePoppedBefore += totalL1MessagePoppedInChunk

		totalL1CommitGas += CalldataNonZeroByteGas * (32 * (totalL1MessagePoppedInChunk + 255) / 256)
		totalL1CommitGas += GetKeccak256Gas(89 + 32*(totalL1MessagePoppedInChunk+255)/256)

		var totalL1CommitCalldataSize uint64
		chunkL1CommitCalldataSize, err := o.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += chunkL1CommitCalldataSize
		totalL1CommitGas += GetMemoryExpansionCost(totalL1CommitCalldataSize)
	}

	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (o *DACodecV1) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	var totalL1CommitCalldataSize uint64
	for _, chunk := range b.Chunks {
		chunkL1CommitCalldataSize, err := o.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += chunkL1CommitCalldataSize
	}
	return totalL1CommitCalldataSize, nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
func (o *DACodecV1) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
func (o *DACodecV1) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	return true, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (o *DACodecV1) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	return 0, 0, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (o *DACodecV1) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	return 0, 0, nil
}

// SetCompression enables or disables compression.
func (o *DACodecV1) SetCompression(enable bool) {}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func (o *DACodecV1) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	var dataBytes []byte
	totalL1MessagePoppedBeforeChunk := totalL1MessagePoppedBefore

	for _, chunk := range chunks {
		daChunk, err := o.NewDAChunk(chunk, totalL1MessagePoppedBeforeChunk)
		if err != nil {
			return common.Hash{}, err
		}
		totalL1MessagePoppedBeforeChunk += chunk.NumL1Messages(totalL1MessagePoppedBeforeChunk)
		chunkHash, err := daChunk.Hash()
		if err != nil {
			return common.Hash{}, err
		}
		dataBytes = append(dataBytes, chunkHash.Bytes()...)
	}

	dataHash := crypto.Keccak256Hash(dataBytes)
	return dataHash, nil
}

// DecodeDAChunks takes a byte slice and decodes it into a []DAChunk
func (o *DACodecV1) DecodeDAChunks(bytes [][]byte) ([]DAChunk, error) {
	return (&DACodecV0{}).DecodeDAChunks(bytes)
}
