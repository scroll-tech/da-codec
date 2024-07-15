package codecv2

/*
#include <stdint.h>
char* compress_scroll_batch_bytes(uint8_t* src, uint64_t src_size, uint8_t* output_buf, uint64_t *output_buf_size);
*/
import "C"

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/klauspost/compress/zstd"
	"github.com/scroll-tech/go-ethereum/accounts/abi"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/log"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv1"
)

// BLSModulus is the BLS modulus defined in EIP-4844.
var BLSModulus = codecv1.BLSModulus

// MaxNumChunks is the maximum number of chunks that a batch can contain.
const MaxNumChunks = 45

const BlockContextByteSize = 60

// DABlock represents a Data Availability Block.
type DABlock = codecv1.DABlock

// DAChunk groups consecutive DABlocks with their transactions.
type DAChunk = codecv1.DAChunk

// DAChunkRawTx groups consecutive DABlocks with their transactions.
type DAChunkRawTx codecv1.DAChunkRawTx

// DABatch contains metadata about a batch of DAChunks.
type DABatch struct {
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

// NewDABlock creates a new DABlock from the given encoding.Block and the total number of L1 messages popped before.
func NewDABlock(block *encoding.Block, totalL1MessagePoppedBefore uint64) (*DABlock, error) {
	return codecv1.NewDABlock(block, totalL1MessagePoppedBefore)
}

// NewDAChunk creates a new DAChunk from the given encoding.Chunk and the total number of L1 messages popped before.
func NewDAChunk(chunk *encoding.Chunk, totalL1MessagePoppedBefore uint64) (*DAChunk, error) {
	return codecv1.NewDAChunk(chunk, totalL1MessagePoppedBefore)
}

// DecodeDAChunksRawTx takes a byte slice and decodes it into a []DAChunkRawTx.
func DecodeDAChunksRawTx(bytes [][]byte) ([]*DAChunkRawTx, error) {
	var chunks []*DAChunkRawTx
	for _, chunk := range bytes {
		if len(chunk) < 1 {
			return nil, fmt.Errorf("invalid chunk, length is less than 1")
		}

		numBlocks := int(chunk[0])
		if len(chunk) < 1+numBlocks*BlockContextByteSize {
			return nil, fmt.Errorf("chunk size doesn't match with numBlocks, byte length of chunk: %v, expected length: %v", len(chunk), 1+numBlocks*BlockContextByteSize)
		}

		blocks := make([]*DABlock, numBlocks)
		for i := 0; i < numBlocks; i++ {
			startIdx := 1 + i*BlockContextByteSize // add 1 to skip numBlocks byte
			endIdx := startIdx + BlockContextByteSize
			blocks[i] = &DABlock{}
			err := blocks[i].Decode(chunk[startIdx:endIdx])
			if err != nil {
				return nil, err
			}
		}

		var transactions []types.Transactions

		chunks = append(chunks, &DAChunkRawTx{
			Blocks:       blocks,
			Transactions: transactions,
		})
	}
	return chunks, nil
}

// NewDABatch creates a DABatch from the provided encoding.Batch.
func NewDABatch(batch *encoding.Batch) (*DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > MaxNumChunks {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	// batch data hash
	dataHash, err := ComputeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := encoding.ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, err := ConstructBlobPayload(batch.Chunks, false /* no mock */)
	if err != nil {
		return nil, err
	}

	daBatch := DABatch{
		Version:                uint8(encoding.CodecV2),
		BatchIndex:             batch.Index,
		L1MessagePopped:        totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore,
		TotalL1MessagePopped:   totalL1MessagePoppedAfter,
		DataHash:               dataHash,
		BlobVersionedHash:      blobVersionedHash,
		ParentBatchHash:        batch.ParentBatchHash,
		SkippedL1MessageBitmap: bitmapBytes,
		blob:                   blob,
		z:                      z,
	}

	return &daBatch, nil
}

// ComputeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func ComputeBatchDataHash(chunks []*encoding.Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	return codecv1.ComputeBatchDataHash(chunks, totalL1MessagePoppedBefore)
}

// ConstructBlobPayload constructs the 4844 blob payload.
func ConstructBlobPayload(chunks []*encoding.Chunk, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + MaxNumChunks*4

	// the raw (un-compressed and un-padded) blob payload
	blobBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+MaxNumChunks+1)*32)

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
				rlpTxData, err := encoding.ConvertTxDataToRLPEncoding(tx, useMockTxData)
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

	// if we have fewer than MaxNumChunks chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < MaxNumChunks; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(blobBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	// compress blob bytes
	compressedBlobBytes, err := compressScrollBatchBytes(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, err
	}

	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(blobBytes) > 131072 {
		// Check compressed data compatibility.
		if err = encoding.CheckCompressedDataCompatibility(compressedBlobBytes); err != nil {
			log.Error("ConstructBlobPayload: compressed data compatibility check failed", "err", err, "uncompressedBlobBytes", hex.EncodeToString(blobBytes), "compressedBlobBytes", hex.EncodeToString(compressedBlobBytes))
			return nil, common.Hash{}, nil, err
		}
	}

	// convert raw data to BLSFieldElements
	blob, err := MakeBlobCanonical(compressedBlobBytes)
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
	copy(challengePreimage[(1+MaxNumChunks)*32:], blobVersionedHash[:])

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

// DecodeTxsFromBlob decodes txs from blob bytes and writes to chunks
func DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	compressedBytes := codecv1.BytesFromBlobCanonical(blob)
	magics := []byte{0x28, 0xb5, 0x2f, 0xfd}

	blobBytes, err := decompressScrollBatchBytes(append(magics, compressedBytes[:]...))
	if err != nil {
		return err
	}

	numChunks := int(binary.BigEndian.Uint16(blobBytes[0:2]))
	if numChunks != len(chunks) {
		return fmt.Errorf("blob chunk number is not same as calldata, blob num chunks: %d, calldata num chunks: %d", numChunks, len(chunks))
	}
	index := 2 + MaxNumChunks*4
	for chunkID, chunk := range chunks {
		var transactions []types.Transactions
		chunkSize := int(binary.BigEndian.Uint32(blobBytes[2+4*chunkID : 2+4*chunkID+4]))

		chunkBytes := blobBytes[index : index+chunkSize]
		curIndex := 0
		for _, block := range chunk.Blocks {
			var blockTransactions types.Transactions
			var txNum = int(block.NumTransactions - block.NumL1Messages)
			for i := 0; i < txNum; i++ {
				tx, nextIndex, err := codecv1.GetNextTx(chunkBytes, curIndex)
				if err != nil {
					return fmt.Errorf("couldn't decode next tx from blob bytes: %w, index: %d", err, index+curIndex+4)
				}
				curIndex = nextIndex
				blockTransactions = append(blockTransactions, tx)
			}
			transactions = append(transactions, blockTransactions)
		}
		chunk.Transactions = transactions
		index += chunkSize
	}
	return nil
}

// MakeBlobCanonical converts the raw blob data into the canonical blob representation of 4096 BLSFieldElements.
func MakeBlobCanonical(blobBytes []byte) (*kzg4844.Blob, error) {
	return codecv1.MakeBlobCanonical(blobBytes)
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func NewDABatchFromBytes(data []byte) (*DABatch, error) {
	if len(data) < 121 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 121 bytes but got %d", len(data))
	}

	b := &DABatch{
		Version:                data[0],
		BatchIndex:             binary.BigEndian.Uint64(data[1:9]),
		L1MessagePopped:        binary.BigEndian.Uint64(data[9:17]),
		TotalL1MessagePopped:   binary.BigEndian.Uint64(data[17:25]),
		DataHash:               common.BytesToHash(data[25:57]),
		BlobVersionedHash:      common.BytesToHash(data[57:89]),
		ParentBatchHash:        common.BytesToHash(data[89:121]),
		SkippedL1MessageBitmap: data[121:],
	}

	return b, nil
}

// Encode serializes the DABatch into bytes.
func (b *DABatch) Encode() []byte {
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
func (b *DABatch) Hash() common.Hash {
	bytes := b.Encode()
	return crypto.Keccak256Hash(bytes)
}

// BlobDataProof computes the abi-encoded blob verification data.
func (b *DABatch) BlobDataProof() ([]byte, error) {
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
func (b *DABatch) Blob() *kzg4844.Blob {
	return b.blob
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func EstimateChunkL1CommitBatchSizeAndBlobSize(c *encoding.Chunk) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayload([]*encoding.Chunk{c})
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), CalculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func EstimateBatchL1CommitBatchSizeAndBlobSize(b *encoding.Batch) (uint64, uint64, error) {
	batchBytes, err := constructBatchPayload(b.Chunks)
	if err != nil {
		return 0, 0, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return 0, 0, err
	}
	return uint64(len(batchBytes)), CalculatePaddedBlobSize(uint64(len(blobBytes))), nil
}

// CheckChunkCompressedDataCompatibility checks the compressed data compatibility for a batch built from a single chunk.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func CheckChunkCompressedDataCompatibility(c *encoding.Chunk) (bool, error) {
	batchBytes, err := constructBatchPayload([]*encoding.Chunk{c})
	if err != nil {
		return false, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= 131072 {
		return true, nil
	}
	if err = encoding.CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckChunkCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "uncompressedBlobBytes", hex.EncodeToString(batchBytes), "compressedBlobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// CheckBatchCompressedDataCompatibility checks the compressed data compatibility for a batch.
// It constructs a batch payload, compresses the data, and checks the compressed data compatibility if the uncompressed data exceeds 128 KiB.
func CheckBatchCompressedDataCompatibility(b *encoding.Batch) (bool, error) {
	batchBytes, err := constructBatchPayload(b.Chunks)
	if err != nil {
		return false, err
	}
	blobBytes, err := compressScrollBatchBytes(batchBytes)
	if err != nil {
		return false, err
	}
	// Only apply this check when the uncompressed batch data has exceeded 128 KiB.
	if len(batchBytes) <= 131072 {
		return true, nil
	}
	if err = encoding.CheckCompressedDataCompatibility(blobBytes); err != nil {
		log.Warn("CheckBatchCompressedDataCompatibility: compressed data compatibility check failed", "err", err, "uncompressedBlobBytes", hex.EncodeToString(batchBytes), "compressedBlobBytes", hex.EncodeToString(blobBytes))
		return false, nil
	}
	return true, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func EstimateChunkL1CommitCalldataSize(c *encoding.Chunk) uint64 {
	return codecv1.EstimateChunkL1CommitCalldataSize(c)
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func EstimateBatchL1CommitCalldataSize(b *encoding.Batch) uint64 {
	return codecv1.EstimateBatchL1CommitCalldataSize(b)
}

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func EstimateBlockL1CommitGas(b *encoding.Block) uint64 {
	return codecv1.EstimateBlockL1CommitGas(b)
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func EstimateChunkL1CommitGas(c *encoding.Chunk) uint64 {
	return codecv1.EstimateChunkL1CommitGas(c)
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func EstimateBatchL1CommitGas(b *encoding.Batch) uint64 {
	return codecv1.EstimateBatchL1CommitGas(b)
}

// constructBatchPayload constructs the batch payload.
// This function is only used in compressed batch payload length estimation.
func constructBatchPayload(chunks []*encoding.Chunk) ([]byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + MaxNumChunks*4

	// the raw (un-compressed and un-padded) blob payload
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

// CalculatePaddedBlobSize calculates the required size on blob storage
// where every 32 bytes can store only 31 bytes of actual data, with the first byte being zero.
func CalculatePaddedBlobSize(dataSize uint64) uint64 {
	return codecv1.CalculatePaddedBlobSize(dataSize)
}

// GetBlobDataProofArgs gets the blob data proof arguments for batch commitment and returns error if initialization fails.
func GetBlobDataProofArgs() (*abi.Arguments, error) {
	return codecv1.GetBlobDataProofArgs()
}

// decompressScrollBatchBytes decompresses the given bytes into scroll batch bytes
func decompressScrollBatchBytes(compressedBytes []byte) ([]byte, error) {
	// decompress data in stream and in batches of bytes, because we don't know actual length of compressed data
	var res []byte
	readBatchSize := 131072
	batchOfBytes := make([]byte, readBatchSize)

	r := bytes.NewReader(compressedBytes)
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	for {
		i, err := zr.Read(batchOfBytes)
		res = append(res, batchOfBytes[:i]...) // append already decoded bytes even if we meet error
		if i < readBatchSize || err != nil {
			break
		}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("failed to decompress blob bytes")
	}
	return res, nil
}
