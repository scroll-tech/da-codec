package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

type DACodecV1 struct {
	DACodecV0
}

// Version returns the codec version.
func (d *DACodecV1) Version() CodecVersion {
	return CodecV1
}

// NewDAChunk creates a new DAChunk from the given Chunk and the total number of L1 messages popped before.
func (d *DACodecV1) NewDAChunk(chunk *Chunk, totalL1MessagePoppedBefore uint64) (DAChunk, error) {
	var blocks []DABlock
	var txs [][]*types.TransactionData

	if chunk == nil {
		return nil, errors.New("chunk is nil")
	}

	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > 255 {
		return nil, errors.New("number of blocks exceeds 1 byte")
	}

	for _, block := range chunk.Blocks {
		b, err := d.NewDABlock(block, totalL1MessagePoppedBefore)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
		totalL1MessagePoppedBefore += block.NumL1Messages(totalL1MessagePoppedBefore)
		txs = append(txs, block.Transactions)
	}

	daChunk := newDAChunkV1(
		blocks, // blocks
		txs,    // transactions
	)

	return daChunk, nil
}

// DecodeDAChunksRawTx takes a byte slice and decodes it into a []*DAChunkRawTx.
// Beginning from codecv1 tx data posted to blobs, not to chunk bytes in calldata
func (d *DACodecV1) DecodeDAChunksRawTx(bytes [][]byte) ([]*DAChunkRawTx, error) {
	var chunks []*DAChunkRawTx
	for _, chunk := range bytes {
		if len(chunk) < 1 {
			return nil, fmt.Errorf("invalid chunk, length is less than 1")
		}

		numBlocks := int(chunk[0])
		if len(chunk) < 1+numBlocks*blockContextByteSize {
			return nil, fmt.Errorf("chunk size doesn't match with numBlocks, byte length of chunk: %v, expected length: %v", len(chunk), 1+numBlocks*blockContextByteSize)
		}

		blocks := make([]DABlock, numBlocks)
		for i := 0; i < numBlocks; i++ {
			startIdx := 1 + i*blockContextByteSize // add 1 to skip numBlocks byte
			endIdx := startIdx + blockContextByteSize
			blocks[i] = &daBlockV0{}
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
func (d *DACodecV1) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	batchBytes := bytesFromBlobCanonical(blob)
	return decodeTxsFromBytes(batchBytes[:], chunks, int(d.MaxNumChunksPerBatch()))
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV1) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > int(d.MaxNumChunksPerBatch()) {
		return nil, errors.New("too many chunks in batch")
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("too few chunks in batch")
	}

	// batch data hash
	dataHash, err := d.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// skipped L1 messages bitmap
	bitmapBytes, totalL1MessagePoppedAfter, err := ConstructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}

	// blob payload
	blob, blobVersionedHash, z, err := d.constructBlobPayload(batch.Chunks, int(d.MaxNumChunksPerBatch()), false /* no mock */)
	if err != nil {
		return nil, err
	}

	daBatch := newDABatchV1(
		uint8(CodecV1), // version
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

// constructBlobPayload constructs the 4844 blob payload.
func (d *DACodecV1) constructBlobPayload(chunks []*Chunk, maxNumChunksPerBatch int, useMockTxData bool) (*kzg4844.Blob, common.Hash, *kzg4844.Point, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + maxNumChunksPerBatch*4

	// the raw (un-padded) blob payload
	blobBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+maxNumChunksPerBatch+1)*32)

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
				rlpTxData, err := convertTxDataToRLPEncoding(tx, useMockTxData)
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

	// if we have fewer than MaxNumChunksPerBatch chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < maxNumChunksPerBatch; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[32+chunkID*32:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(blobBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	// convert raw data to BLSFieldElements
	blob, err := makeBlobCanonical(blobBytes)
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
	copy(challengePreimage[(1+maxNumChunksPerBatch)*32:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), blsModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	start := 32 - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (d *DACodecV1) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < 121 {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least 121 bytes but got %d", len(data))
	}

	if CodecVersion(data[0]) != CodecV1 {
		return nil, fmt.Errorf("invalid codec version: %d, expected: %d", data[0], CodecV1)
	}

	b := newDABatchV1(
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

func (d *DACodecV1) chunkL1CommitBlobDataSize(c *Chunk) (uint64, error) {
	var dataSize uint64
	for _, block := range c.Blocks {
		for _, tx := range block.Transactions {
			if tx.Type == types.L1MessageTxType {
				continue
			}

			rlpTxData, err := convertTxDataToRLPEncoding(tx, false /* no mock */)
			if err != nil {
				return 0, err
			}
			dataSize += uint64(len(rlpTxData))
		}
	}
	return dataSize, nil
}

// EstimateBlockL1CommitGas calculates the total L1 commit gas for this block approximately.
func (d *DACodecV1) EstimateBlockL1CommitGas(b *Block) (uint64, error) {
	var total uint64
	var numL1Messages uint64
	for _, txData := range b.Transactions {
		if txData.Type == types.L1MessageTxType {
			numL1Messages++
			continue
		}
	}

	total += calldataNonZeroByteGas * blockContextByteSize

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
func (d *DACodecV1) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	var totalTxNum uint64
	var totalL1CommitGas uint64
	for _, block := range c.Blocks {
		totalTxNum += uint64(len(block.Transactions))
		blockL1CommitGas, err := d.EstimateBlockL1CommitGas(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += blockL1CommitGas
	}

	numBlocks := uint64(len(c.Blocks))
	totalL1CommitGas += 100 * numBlocks        // numBlocks times warm sload
	totalL1CommitGas += calldataNonZeroByteGas // numBlocks field of chunk encoding in calldata

	totalL1CommitGas += getKeccak256Gas(58*numBlocks + 32*totalTxNum) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
func (d *DACodecV1) EstimateBlockL1CommitCalldataSize(b *Block) (uint64, error) {
	return blockContextByteSize, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (d *DACodecV1) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return uint64(blockContextByteSize * len(c.Blocks)), nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a single chunk.
func (d *DACodecV1) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	metadataSize := 2 + 4*d.MaxNumChunksPerBatch()
	batchDataSize, err := d.chunkL1CommitBlobDataSize(c)
	if err != nil {
		return 0, 0, err
	}
	blobSize := calculatePaddedBlobSize(metadataSize + batchDataSize)
	return blobSize, blobSize, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit uncompressed batch size and compressed blob size for a batch.
func (d *DACodecV1) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	metadataSize := 2 + 4*d.MaxNumChunksPerBatch()
	var batchDataSize uint64
	for _, c := range b.Chunks {
		chunkDataSize, err := d.chunkL1CommitBlobDataSize(c)
		if err != nil {
			return 0, 0, err
		}
		batchDataSize += chunkDataSize
	}
	blobSize := calculatePaddedBlobSize(metadataSize + batchDataSize)
	return blobSize, blobSize, nil
}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a badge in the contracts,
// the latter is used in the public input to the provers.
func (d *DACodecV1) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	var dataBytes []byte
	totalL1MessagePoppedBeforeChunk := totalL1MessagePoppedBefore

	for _, chunk := range chunks {
		daChunk, err := d.NewDAChunk(chunk, totalL1MessagePoppedBeforeChunk)
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
