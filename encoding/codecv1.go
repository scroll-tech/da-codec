package encoding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
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
	if chunk == nil {
		return nil, errors.New("chunk is nil")
	}

	if len(chunk.Blocks) == 0 {
		return nil, errors.New("number of blocks is 0")
	}

	if len(chunk.Blocks) > math.MaxUint8 {
		return nil, fmt.Errorf("number of blocks (%d) exceeds maximum allowed (%d)", len(chunk.Blocks), math.MaxUint8)
	}

	blocks := make([]DABlock, 0, len(chunk.Blocks))
	txs := make([][]*types.TransactionData, 0, len(chunk.Blocks))

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
func (d *DACodecV1) DecodeDAChunksRawTx(chunkBytes [][]byte) ([]*DAChunkRawTx, error) {
	chunks := make([]*DAChunkRawTx, 0, len(chunkBytes))
	for _, chunk := range chunkBytes {
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

		chunks = append(chunks, &DAChunkRawTx{
			Blocks:       blocks,
			Transactions: nil, // Transactions field is still empty in the phase of DecodeDAChunksRawTx, because txs moved to blobs and filled in DecodeTxsFromBlob method.
		})
	}
	return chunks, nil
}

// DecodeTxsFromBlob decodes txs from blob bytes and writes to chunks
func (d *DACodecV1) DecodeTxsFromBlob(blob *kzg4844.Blob, chunks []*DAChunkRawTx) error {
	batchBytes := bytesFromBlobCanonical(blob)
	return decodeTxsFromBytes(batchBytes[:], chunks, d.MaxNumChunksPerBatch())
}

// NewDABatch creates a DABatch from the provided Batch.
func (d *DACodecV1) NewDABatch(batch *Batch) (DABatch, error) {
	// this encoding can only support a fixed number of chunks per batch
	if len(batch.Chunks) > d.MaxNumChunksPerBatch() {
		return nil, fmt.Errorf("too many chunks in batch: got %d, maximum allowed is %d", len(batch.Chunks), d.MaxNumChunksPerBatch())
	}

	if len(batch.Chunks) == 0 {
		return nil, errors.New("batch must contain at least one chunk")
	}

	// batch data hash
	dataHash, err := d.computeBatchDataHash(batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, fmt.Errorf("failed to compute batch data hash, index: %d, err: %w", batch.Index, err)
	}

	// skipped L1 messages bitmap
	skippedL1MessageBitmap, totalL1MessagePoppedAfter, err := constructSkippedBitmap(batch.Index, batch.Chunks, batch.TotalL1MessagePoppedBefore)
	if err != nil {
		return nil, fmt.Errorf("failed to construct skipped bitmap, index: %d, err: %w", batch.Index, err)
	}

	// blob payload
	blob, blobVersionedHash, z, err := d.constructBlobPayload(batch.Chunks, d.MaxNumChunksPerBatch())
	if err != nil {
		return nil, fmt.Errorf("failed to construct blob payload, index: %d, err: %w", batch.Index, err)
	}

	if totalL1MessagePoppedAfter < batch.TotalL1MessagePoppedBefore {
		return nil, fmt.Errorf("batch index: %d, totalL1MessagePoppedAfter (%d) is less than batch.TotalL1MessagePoppedBefore (%d)", batch.Index, totalL1MessagePoppedAfter, batch.TotalL1MessagePoppedBefore)
	}
	l1MessagePopped := totalL1MessagePoppedAfter - batch.TotalL1MessagePoppedBefore

	daBatch := newDABatchV1(
		CodecV1,                   // version
		batch.Index,               // batchIndex
		l1MessagePopped,           // l1MessagePopped
		totalL1MessagePoppedAfter, // totalL1MessagePopped
		dataHash,                  // dataHash
		blobVersionedHash,         // blobVersionedHash
		batch.ParentBatchHash,     // parentBatchHash
		skippedL1MessageBitmap,    // skippedL1MessageBitmap
		blob,                      // blob
		z,                         // z
	)

	return daBatch, nil
}

// constructBlobPayload constructs the 4844 blob payload.
func (d *DACodecV1) constructBlobPayload(chunks []*Chunk, maxNumChunksPerBatch int) (*kzg4844.Blob, common.Hash, *kzg4844.Point, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + maxNumChunksPerBatch*4

	// the raw (un-padded) blob payload
	blobBytes := make([]byte, metadataLength)

	// challenge digest preimage
	// 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
	challengePreimage := make([]byte, (1+maxNumChunksPerBatch+1)*common.HashLength)

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
				rlpTxData, err := convertTxDataToRLPEncoding(tx)
				if err != nil {
					return nil, common.Hash{}, nil, fmt.Errorf("failed to convert txData to RLP encoding: %w", err)
				}
				blobBytes = append(blobBytes, rlpTxData...)
			}
		}

		// blob metadata: chunki_size
		chunkSize := len(blobBytes) - currentChunkStartIndex
		binary.BigEndian.PutUint32(blobBytes[2+4*chunkID:], uint32(chunkSize))

		// challenge: compute chunk data hash
		chunkDataHash = crypto.Keccak256Hash(blobBytes[currentChunkStartIndex:])
		copy(challengePreimage[common.HashLength+chunkID*common.HashLength:], chunkDataHash[:])
	}

	// if we have fewer than maxNumChunksPerBatch chunks, the rest
	// of the blob metadata is correctly initialized to 0,
	// but we need to add padding to the challenge preimage
	for chunkID := len(chunks); chunkID < maxNumChunksPerBatch; chunkID++ {
		// use the last chunk's data hash as padding
		copy(challengePreimage[common.HashLength+chunkID*common.HashLength:], chunkDataHash[:])
	}

	// challenge: compute metadata hash
	hash := crypto.Keccak256Hash(blobBytes[0:metadataLength])
	copy(challengePreimage[0:], hash[:])

	// convert raw data to BLSFieldElements
	blob, err := makeBlobCanonical(blobBytes)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to convert blobBytes to canonical form: %w", err)
	}

	// compute blob versioned hash
	c, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return nil, common.Hash{}, nil, fmt.Errorf("failed to create blob commitment: %w", err)
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &c)

	// challenge: append blob versioned hash
	copy(challengePreimage[(1+maxNumChunksPerBatch)*common.HashLength:], blobVersionedHash[:])

	// compute z = challenge_digest % BLS_MODULUS
	challengeDigest := crypto.Keccak256Hash(challengePreimage)
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), blsModulus)
	pointBytes := pointBigInt.Bytes()

	// the challenge point z
	var z kzg4844.Point
	if len(pointBytes) > kzgPointByteSize {
		return nil, common.Hash{}, nil, fmt.Errorf("pointBytes length exceeds %d bytes, got %d bytes", kzgPointByteSize, len(pointBytes))
	}
	start := kzgPointByteSize - len(pointBytes)
	copy(z[start:], pointBytes)

	return blob, blobVersionedHash, &z, nil
}

// NewDABatchFromBytes decodes the given byte slice into a DABatch.
// Note: This function only populates the batch header, it leaves the blob-related fields empty.
func (d *DACodecV1) NewDABatchFromBytes(data []byte) (DABatch, error) {
	if len(data) < daBatchV1EncodedMinLength {
		return nil, fmt.Errorf("insufficient data for DABatch, expected at least %d bytes but got %d", daBatchV1EncodedMinLength, len(data))
	}

	if CodecVersion(data[daBatchOffsetVersion]) != CodecV1 {
		return nil, fmt.Errorf("codec version mismatch: expected %d but found %d", CodecV1, data[daBatchOffsetVersion])
	}

	return newDABatchV1(
		CodecVersion(data[daBatchOffsetVersion]),                                                          // version
		binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV1OffsetL1MessagePopped]),             // batchIndex
		binary.BigEndian.Uint64(data[daBatchV1OffsetL1MessagePopped:daBatchV1OffsetTotalL1MessagePopped]), // l1MessagePopped
		binary.BigEndian.Uint64(data[daBatchV1OffsetTotalL1MessagePopped:daBatchOffsetDataHash]),          // totalL1MessagePopped
		common.BytesToHash(data[daBatchOffsetDataHash:daBatchV1OffsetBlobVersionedHash]),                  // dataHash
		common.BytesToHash(data[daBatchV1OffsetBlobVersionedHash:daBatchV1OffsetParentBatchHash]),         // blobVersionedHash
		common.BytesToHash(data[daBatchV1OffsetParentBatchHash:daBatchV1OffsetSkippedL1MessageBitmap]),    // parentBatchHash
		data[daBatchV1OffsetSkippedL1MessageBitmap:],                                                      // skippedL1MessageBitmap
		nil, // blob
		nil, // z
	), nil
}

func (d *DACodecV1) chunkL1CommitBlobDataSize(c *Chunk) (uint64, error) {
	var dataSize uint64
	for _, block := range c.Blocks {
		for _, tx := range block.Transactions {
			if tx.Type == types.L1MessageTxType {
				continue
			}

			rlpTxData, err := convertTxDataToRLPEncoding(tx)
			if err != nil {
				return 0, fmt.Errorf("failed to convert txData to RLP encoding: %w", err)
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
	total += coldSloadGas * numL1Messages // numL1Messages times cold sload in L1MessageQueue

	// staticcall
	total += warmAddressAccessGas * numL1Messages // numL1Messages times call to L1MessageQueue
	total += warmAddressAccessGas * numL1Messages // numL1Messages times warm address access to L1MessageQueue

	total += getMemoryExpansionCost(functionSignatureBytes+defaultParameterBytes) * numL1Messages // staticcall to proxy
	total += warmAddressAccessGas * numL1Messages                                                 // read admin in proxy
	total += warmAddressAccessGas * numL1Messages                                                 // read impl in proxy
	total += warmAddressAccessGas * numL1Messages                                                 // access impl
	total += getMemoryExpansionCost(functionSignatureBytes+defaultParameterBytes) * numL1Messages // delegatecall to impl

	return total, nil
}

// EstimateChunkL1CommitGas calculates the total L1 commit gas for this chunk approximately.
func (d *DACodecV1) EstimateChunkL1CommitGas(c *Chunk) (uint64, error) {
	var totalNonSkippedL1Messages uint64
	var totalL1CommitGas uint64
	for _, block := range c.Blocks {
		transactions := uint64(len(block.Transactions))
		l2Transactions := block.NumL2Transactions()
		if transactions < l2Transactions {
			return 0, fmt.Errorf("number of L2 transactions (%d) exceeds total transactions (%d)", l2Transactions, transactions)
		}
		totalNonSkippedL1Messages += transactions - l2Transactions
		blockL1CommitGas, err := d.EstimateBlockL1CommitGas(block)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += blockL1CommitGas
	}

	numBlocks := uint64(len(c.Blocks))
	totalL1CommitGas += warmSloadGas * numBlocks // numBlocks times warm sload
	totalL1CommitGas += calldataNonZeroByteGas   // numBlocks field of chunk encoding in calldata

	totalL1CommitGas += getKeccak256Gas(58*numBlocks + common.HashLength*totalNonSkippedL1Messages) // chunk hash
	return totalL1CommitGas, nil
}

// EstimateBatchL1CommitGas calculates the total L1 commit gas for this batch approximately.
func (d *DACodecV1) EstimateBatchL1CommitGas(b *Batch) (uint64, error) {
	var totalL1CommitGas uint64

	// Add extra gas costs
	totalL1CommitGas += extraGasCost           // constant to account for ops like _getAdmin, _implementation, _requireNotPaused, etc
	totalL1CommitGas += 4 * coldSloadGas       // 4 one-time cold sload for commitBatch
	totalL1CommitGas += sstoreGas              // 1 time sstore
	totalL1CommitGas += baseTxGas              // base gas for tx
	totalL1CommitGas += calldataNonZeroByteGas // version in calldata

	// adjusting gas:
	// add 1 time cold sload (2100 gas) for L1MessageQueue
	// add 1 time cold address access (2600 gas) for L1MessageQueue
	// minus 1 time warm sload (100 gas) & 1 time warm address access (100 gas)
	totalL1CommitGas += (coldSloadGas + coldAddressAccessGas - warmSloadGas - warmAddressAccessGas)
	totalL1CommitGas += getKeccak256Gas(daBatchV0EncodedMinLength + skippedL1MessageBitmapByteSize)           // parent batch header hash, length is estimated as (constant part) + (1 skippedL1MessageBitmap)
	totalL1CommitGas += calldataNonZeroByteGas * (daBatchV0EncodedMinLength + skippedL1MessageBitmapByteSize) // parent batch header in calldata

	// adjust batch data hash gas cost
	totalL1CommitGas += getKeccak256Gas(uint64(common.HashLength * len(b.Chunks)))

	totalL1MessagePoppedBefore := b.TotalL1MessagePoppedBefore

	for _, chunk := range b.Chunks {
		chunkL1CommitGas, err := d.EstimateChunkL1CommitGas(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += chunkL1CommitGas

		totalL1MessagePoppedInChunk := chunk.NumL1Messages(totalL1MessagePoppedBefore)
		totalL1MessagePoppedBefore += totalL1MessagePoppedInChunk

		totalL1CommitGas += calldataNonZeroByteGas * (skippedL1MessageBitmapByteSize * (totalL1MessagePoppedInChunk + 255) / 256)
		totalL1CommitGas += getKeccak256Gas(daBatchV3OffsetParentBatchHash + skippedL1MessageBitmapByteSize*(totalL1MessagePoppedInChunk+255)/256)

		chunkL1CommitCalldataSize, err := d.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitGas += getMemoryExpansionCost(chunkL1CommitCalldataSize)
	}

	return totalL1CommitGas, nil
}

// EstimateBlockL1CommitCalldataSize calculates the calldata size in l1 commit for this block approximately.
func (d *DACodecV1) EstimateBlockL1CommitCalldataSize(_ *Block) (uint64, error) {
	return blockContextByteSize, nil
}

// EstimateChunkL1CommitCalldataSize calculates the calldata size needed for committing a chunk to L1 approximately.
func (d *DACodecV1) EstimateChunkL1CommitCalldataSize(c *Chunk) (uint64, error) {
	return uint64(blockContextByteSize * len(c.Blocks)), nil
}

// EstimateBatchL1CommitCalldataSize calculates the calldata size in l1 commit for this batch approximately.
func (d *DACodecV1) EstimateBatchL1CommitCalldataSize(b *Batch) (uint64, error) {
	var totalL1CommitCalldataSize uint64
	for _, chunk := range b.Chunks {
		chunkL1CommitCalldataSize, err := d.EstimateChunkL1CommitCalldataSize(chunk)
		if err != nil {
			return 0, err
		}
		totalL1CommitCalldataSize += chunkL1CommitCalldataSize
	}
	return totalL1CommitCalldataSize, nil
}

// EstimateChunkL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a single chunk.
func (d *DACodecV1) EstimateChunkL1CommitBatchSizeAndBlobSize(c *Chunk) (uint64, uint64, error) {
	metadataSize := uint64(2 + 4*d.MaxNumChunksPerBatch())
	batchDataSize, err := d.chunkL1CommitBlobDataSize(c)
	if err != nil {
		return 0, 0, err
	}
	blobSize := calculatePaddedBlobSize(metadataSize + batchDataSize)
	return metadataSize + batchDataSize, blobSize, nil
}

// EstimateBatchL1CommitBatchSizeAndBlobSize estimates the L1 commit batch size and blob size for a batch.
func (d *DACodecV1) EstimateBatchL1CommitBatchSizeAndBlobSize(b *Batch) (uint64, uint64, error) {
	metadataSize := uint64(2 + 4*d.MaxNumChunksPerBatch())
	var batchDataSize uint64
	for _, c := range b.Chunks {
		chunkDataSize, err := d.chunkL1CommitBlobDataSize(c)
		if err != nil {
			return 0, 0, err
		}
		batchDataSize += chunkDataSize
	}
	blobSize := calculatePaddedBlobSize(metadataSize + batchDataSize)
	return metadataSize + batchDataSize, blobSize, nil
}

// computeBatchDataHash computes the data hash of the batch.
// Note: The batch hash and batch data hash are two different hashes,
// the former is used for identifying a batch in the contracts,
// the latter is used in the public input to the provers.
func (d *DACodecV1) computeBatchDataHash(chunks []*Chunk, totalL1MessagePoppedBefore uint64) (common.Hash, error) {
	dataBytes := make([]byte, 0, len(chunks)*common.HashLength)
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

// BlobDataProofFromBlobBytes calculates a blob's challenge digest, commitment, and proof from blob bytes.
func (d *DACodecV1) BlobDataProofFromBlobBytes(blobBytes []byte) (common.Hash, kzg4844.Commitment, kzg4844.Proof, error) {
	blob, err := makeBlobCanonical(blobBytes)
	if err != nil {
		return common.Hash{}, kzg4844.Commitment{}, kzg4844.Proof{}, fmt.Errorf("failed to convert blobBytes to canonical form: %w", err)
	}

	commitment, err := kzg4844.BlobToCommitment(blob)
	if err != nil {
		return common.Hash{}, kzg4844.Commitment{}, kzg4844.Proof{}, fmt.Errorf("failed to create blob commitment: %w", err)
	}
	blobVersionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &commitment)

	challengeDigest := crypto.Keccak256Hash(crypto.Keccak256(blobBytes), blobVersionedHash[:])

	// z = challengeDigest % BLS_MODULUS
	pointBigInt := new(big.Int).Mod(new(big.Int).SetBytes(challengeDigest[:]), blsModulus)
	pointBytes := pointBigInt.Bytes()

	var z kzg4844.Point
	if len(pointBytes) > kzgPointByteSize {
		return common.Hash{}, kzg4844.Commitment{}, kzg4844.Proof{}, fmt.Errorf("pointBytes length exceeds %d bytes, got %d bytes", kzgPointByteSize, len(pointBytes))
	}

	start := kzgPointByteSize - len(pointBytes)
	copy(z[start:], pointBytes)

	proof, _, err := kzg4844.ComputeProof(blob, z)
	if err != nil {
		return common.Hash{}, kzg4844.Commitment{}, kzg4844.Proof{}, fmt.Errorf("failed to create KZG proof at point, err: %w, z: %v", err, hex.EncodeToString(z[:]))
	}

	return challengeDigest, commitment, proof, nil
}
