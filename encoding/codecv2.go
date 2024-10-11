package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

type DACodecV2 struct{}

// codecv2MaxNumChunks is the maximum number of chunks that a batch can contain.
const codecv2MaxNumChunks = 45

// Version returns the codec version.
func (o *DACodecV2) Version() CodecVersion {
	return CodecV2
}

// MaxNumChunksPerBatch returns the maximum number of chunks per batch.
func (o *DACodecV2) MaxNumChunksPerBatch() uint64 {
	return codecv2MaxNumChunks
}

// NewDABlock creates a new DABlock from the given Block and the total number of L1 messages popped before.
func (o *DACodecV2) NewDABlock(block *Block, totalL1MessagePoppedBefore uint64) (DABlock, error) {
	if !block.Header.Number.IsUint64() {
		return nil, errors.New("block number is not uint64")
	}

	// note: numL1Messages includes skipped messages
	numL1Messages := block.NumL1Messages(totalL1MessagePoppedBefore)
	if numL1Messages > math.MaxUint16 {
		return nil, errors.New("number of L1 messages exceeds max uint16")
	}

	// note: numTransactions includes skipped messages
	numL2Transactions := block.NumL2Transactions()
	numTransactions := numL1Messages + numL2Transactions
	if numTransactions > math.MaxUint16 {
		return nil, errors.New("number of transactions exceeds max uint16")
	}

	daBlock := NewDABlockV0(
		block.Header.Number.Uint64(), // number
		block.Header.Time,            // timestamp
		block.Header.BaseFee,         // baseFee
		block.Header.GasLimit,        // gasLimit
		uint16(numTransactions),      // numTransactions
		uint16(numL1Messages),        // numL1Messages
	)

	return daBlock, nil
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (o *DACodecV2) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	if chunk == nil {
		return nil, errors.New("chunk is nil")
	}

	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > 255 {
		return nil, errors.New("number of blocks exceeds 1 byte")
	}

	var blocks []DABlock
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

	daChunk := NewDAChunkV1(
		blocks, // blocks
		txs,    // transactions
	)

	return daChunk, nil
}

// DecodeDAChunksRawTx takes a byte slice and decodes it into a []*DAChunkRawTx.
// Beginning from codecv1 tx data posted to blobs, not to chunk bytes in calldata
func (o *DACodecV2) DecodeDAChunksRawTx(bytes [][]byte) ([]*DAChunkRawTx, error) {
	var chunks []*DAChunkRawTx
	for _, chunk := range bytes {
		if len(chunk) < 1 {
			return nil, fmt.Errorf("invalid chunk, length is less than 1")
		}

		numBlocks := int(chunk[0])
		if len(chunk) < 1+numBlocks*BlockContextByteSize {
			return nil, fmt.Errorf("chunk size doesn't match with numBlocks, byte length of chunk: %v, expected length: %v", len(chunk), 1+numBlocks*BlockContextByteSize)
		}

		blocks := make([]DABlock, numBlocks)
		for i := 0; i < numBlocks; i++ {
			startIdx := 1 + i*BlockContextByteSize // add 1 to skip numBlocks byte
			endIdx := startIdx + BlockContextByteSize
			blocks[i] = &DABlockV0{}
			err := blocks[i].Decode(chunk[startIdx:endIdx])
			if err != nil {
				return nil, err
			}
		}

		var transactions []types.Transactions

		chunks = append(chunks, &DAChunkRawTx{
			Blocks:       blocks,
			Transactions: transactions, // Transactions field is still empty in the phase of DecodeDAChunksRawTx, because txs moved to blobs and filled in DecodeTxsFromBlob method.
		})
	}
	return chunks, nil
}

// DecodeTxsFromBlob decodes txs from blob bytes and writes to chunks
func (o *DACodecV2) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	compressedBytes := BytesFromBlobCanonical(blob)
	magics := []byte{0x28, 0xb5, 0x2f, 0xfd}

	batchBytes, err := DecompressScrollBlobToBatch(append(magics, compressedBytes[:]...))
	if err != nil {
		return err
	}
	return DecodeTxsFromBytes(batchBytes, chunks, codecv2MaxNumChunks)
}

// NewDABatch creates a DABatch from the provided Batch.
func (o *DACodecV2) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > codecv2MaxNumChunks {
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
	bitmapBytes, totalL1MessagePoppedAfter, err := ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, _, err := o.constructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	daBatch := NewDABatchV1(
		uint8(CodecV2), // version
		batch.Index,    // batchIndex
		totalL1MessagePoppedAfter-batch.TotalL1MessagePoppedBefore, // l1MessagePopped
		totalL1MessagePoppedAfter,                                  // totalL1MessagePopped
		dataHash,                                                   // dataHash
		batch.ParentBatchHash,                                      // parentBatchHash
		blobVersionedHash,                                          // blobVersionedHash
		bitmapBytes,                                                // skippedL1MessageBitmap
		blob,                                                       // blob
		z,                                                          // z
	)

	return daBatch, nil
}

// NewDABatchWithExpectedBlobVersionedHashes creates a DABatch from the provided Batch.
// It also checks if the blob versioned hashes are as expected.
func (o *DACodecV2) NewDABatchWithExpectedBlobVersionedHashes(batch *Batch, hashes []common.Hash) (DABatch, error) {
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
func (o *DACodecV2) constructBlobPayload(chunks []*Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, []byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + codecv2MaxNumChunks*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
	batchBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+codecv2MaxNumChunks+1)*32)

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

	// if we have fewer than codecv2MaxNumChunks chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < codecv2MaxNumChunks; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(batchBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	// blobBytes represents the compressed blob payload (batchBytes)
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return nil, common.Hash{}, nil, nil, err
	}

	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if !useMockTxData && len(batchBytes) > 131072 {
		// Check compressed data compatibility.
		if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
			log.Error("constructBlobPayload: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
			return nil, common.Hash{}, nil, nil, err
		}
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
	copy(challengePreimage[(1+codecv2MaxNumChunks)*32:], blobVersionedHash[:])

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
func (o *DACodecV2) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 121 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 121 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV2 {
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV2)
	}

	b := NewDABatchV1(
		data[0],                              // version
		binary.BigEndian.Uint64(data[1:9]),   // batchIndex
		binary.BigEndian.Uint64(data[9:17]),  // l1MessagePopped
		binary.BigEndian.Uint64(data[17:25]), // totalL1MessagePopped
		common.BytesToHash(data[25:57]),      // dataHash
		common.BytesToHash(data[89:121]),     // parentBatchHash
		common.BytesToHash(data[57:89]),      // blobVersionedHash
		data[121:],                           // skippedL1MessageBitmap
		nil,                                  // blob
		nil,                                  // z
	)

	return b, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (o *DACodecV2) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob([]*Chunk{c}, o)
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), calculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (o *DACodecV2) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayloadInBlob(b.Chunks, o)
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), calculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (o *DACodecV2) CheckChunkCompressedDataCompatibility(c *Chunk) (bool, error) {
	batchBytes, err := constructBatchPayloadInBlob([]*Chunk{c}, o)
	if err != nil {
		return false, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= 131072 {
		return true, nil
	}
	if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckChunkCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func (o *DACodecV2) CheckBatchCompressedDataCompatibility(b *Batch) (bool, error) {
	batchBytes, err := constructBatchPayloadInBlob(b.Chunks, o)
	if err != nil {
		return false, err
	}
	blobBytes, err := zstd.CompressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= 131072 {
		return true, nil
	}
	if err = CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckBatchCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "batchBytes", hex.EncodeToString(batchBytes), "blobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
func (o *DACodecV2) EstimateBlockL1CommitCalldataSize(b *Block) (uint64, error) {
	return BlockContextByteSize, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (o *DACodecV2) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return uint64(BlockContextByteSize * len(c.Blocks)), nil
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (o *DACodecV2) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
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

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func (o *DACodecV2) EstimateBlockL1CommitGas(b *Block) (uint64, error) {
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

	total += getMemoryExpansionCost(36) * numL1Messages // staticcall to proxy
	total += 100 * numL1Messages                        // read admin in proxy
	total += 100 * numL1Messages                        // read impl in proxy
	total += 100 * numL1Messages                        // access impl
	total += getMemoryExpansionCost(36) * numL1Messages // delegatecall to impl

	return total, nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (o *DACodecV2) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
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

	totalL1CommitGas += getKeccak256Gas(58*numBlocks + 32*totalNonSkippedL1Messages) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (o *DACodecV2) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
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
	totalL1CommitGas += getKeccak256Gas(89 + 32)           // parent batch header hash, length is estimated as 89 (constant part)+ 32 (1 skippedL1MessageBitmap)
	totalL1CommitGas += CalldataNonZeroByteGas * (89 + 32) // parent batch header in calldata

	// adjust batch data hash gas cost
	totalL1CommitGas += getKeccak256Gas(uint64(32 * len(b.Chunks)))

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
		totalL1CommitGas += getKeccak256Gas(89 + 32*(totalL1MessagePoppedInChunk+255)/256)

		chunkL1CommitCalldataSize, err := o.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += getMemoryExpansionCost(chunkL1CommitCalldataSize)
	}

	return totalL1CommitGas, nil
}

// SetCompression enables or disables compression.
func (o *DACodecV2) SetCompression(enable bool) {}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func (o *DACodecV2) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
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

// JSONFromBytes for CodecV2 returns empty values.
func (c *DACodecV2) JSONFromBytes(data []byte) ([]byte, error) {
	// DACodecV2 doesn't need this, so just return empty values
	return nil, nil
}
