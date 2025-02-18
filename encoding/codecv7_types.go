package encoding

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/klauspost/compress/zstd"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// Below is the encoding for `BatchHeader` V7, total 73 bytes.
//   * Field                   Bytes       Type        Index   Comments
//   * version                 1           uint8       0       The batch version
//   * batchIndex              8           uint64      1       The index of the batch
//   * blobVersionedHash       32          bytes32     9       The versioned hash of the blob with this batch’s data
//   * parentBatchHash         32          bytes32     41      The parent batch hash

const (
	daBatchV7EncodedLength           = 73
	daBatchV7OffsetBlobVersionedHash = 9
	daBatchV7OffsetParentBatchHash   = 41
)

// Below is the encoding format for BlobEnvelopeV7.
//   * Field                   Bytes               Type         Index   Comments
//   * version                 1                   uint8        0       The version of the DA codec (batch/blob)
//   * n_bytes[1]              1                   uint8        1       Value denoting the number of bytes, n_bytes[1]*256^2
//   * n_bytes[2]              1                   uint8        2       Value denoting the number of bytes, n_bytes[2]*256
//   * n_bytes[3]              1                   uint8        3       Value denoting the number of bytes, n_bytes[3]
//   * flag                    1                   bool         4       1-byte flag to denote zstd-encoded/raw bytes
//   * payload                 N                   bytes        5       Possibly zstd-encoded payload bytes
//   * padding                 (4096*31 - (N+5))   bytes        N+5     Padding to align to 4096*31 bytes

const (
	blobEnvelopeV7OffsetVersion        = 0
	blobEnvelopeV7OffsetByteSize       = 1
	blobEnvelopeV7OffsetCompressedFlag = 4
	blobEnvelopeV7OffsetPayload        = 5
)

// Below is the encoding for blobPayloadV7.
//   * Field                       Bytes     Type             Index       Comments
//   * initialL1MessageIndex       8         uint64           0           Queue index of the first L1 message contained in this batch
//   * initialL1MessageQueueHash   32        bytes32          8           Hash of the L1 message queue at the last message in the previous batch
//   * lastL1MessageQueueHash      32        bytes32          40          Hash of the L1 message queue at the last message in this batch
//   * initialL2BlockNumber        8         uint64           72          The initial L2 block number in this batch
//   * numBlocks                   2         uint16           80          The number of blocks in this batch
//   * block[0]                    52        BlockContextV2   82          The first block in this batch
//   * block[i]                    52        BlockContextV2   82+52*i     The (i+1)th block in this batch
//   * block[n-1]                  52        BlockContextV2   82+52*(n-1) The last block in this batch
//   * l2Transactions              dynamic   bytes            82+52*n     L2 transactions for this batch

const (
	blobPayloadV7MinEncodedLength            = 8 + 2*common.HashLength + 8 + 2
	blobPayloadV7OffsetInitialL1MessageIndex = 0
	blobPayloadV7OffsetInitialL1MessageQueue = 8
	blobPayloadV7OffsetLastL1MessageQueue    = 40
	blobPayloadV7OffsetInitialL2BlockNumber  = 72
	blobPayloadV7OffsetNumBlocks             = 80
	blobPayloadV7OffsetBlocks                = 82
)

// Below is the encoding for DABlockV7, total 52 bytes.
//   * Field                   Bytes      Type         Index  Comments
//   * timestamp               8          uint64       0      The timestamp of this block.
//   * baseFee                 32         uint256      8      The base fee of this block.
//   * gasLimit                8          uint64       40     The gas limit of this block.
//   * numTransactions         2          uint16       48     The number of transactions in this block, both L1 & L2 txs.
//   * numL1Messages           2          uint16       50     The number of l1 messages in this block.

const (
	daBlockV7BlockContextEncodedLength = 52
	daBlockV7OffsetTimestamp           = 0
	daBlockV7OffsetBaseFee             = 8
	daBlockV7OffsetGasLimit            = 40
	daBlockV7OffsetNumTransactions     = 48
	daBlockV7OffsetNumL1Messages       = 50
)

// daBatchV7 contains V7 batch metadata and payload.
type daBatchV7 struct {
	version           CodecVersion
	batchIndex        uint64
	blobVersionedHash common.Hash
	parentBatchHash   common.Hash

	blob      *kzg4844.Blob
	blobBytes []byte
}

func newDABatchV7(version CodecVersion, batchIndex uint64, blobVersionedHash, parentBatchHash common.Hash, blob *kzg4844.Blob, blobBytes []byte) (*daBatchV7, error) {
	daBatch := &daBatchV7{
		version:           version,
		batchIndex:        batchIndex,
		blobVersionedHash: blobVersionedHash,
		parentBatchHash:   parentBatchHash,
		blob:              blob,
		blobBytes:         blobBytes,
	}

	return daBatch, nil
}

func decodeDABatchV7(data []byte) (*daBatchV7, error) {
	if len(data) != daBatchV7EncodedLength {
		return nil, fmt.Errorf("invalid data length for DABatchV7, expected %d bytes but got %d", daBatchV7EncodedLength, len(data))
	}

	version := CodecVersion(data[daBatchOffsetVersion])
	batchIndex := binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV7OffsetBlobVersionedHash])
	blobVersionedHash := common.BytesToHash(data[daBatchV7OffsetBlobVersionedHash:daBatchV7OffsetParentBatchHash])
	parentBatchHash := common.BytesToHash(data[daBatchV7OffsetParentBatchHash:daBatchV7EncodedLength])

	return newDABatchV7(version, batchIndex, blobVersionedHash, parentBatchHash, nil, nil)
}

// Encode serializes the dABatchV7 into bytes.
func (b *daBatchV7) Encode() []byte {
	batchBytes := make([]byte, daBatchV7EncodedLength)
	batchBytes[daBatchOffsetVersion] = byte(b.version)
	binary.BigEndian.PutUint64(batchBytes[daBatchOffsetBatchIndex:daBatchV7OffsetBlobVersionedHash], b.batchIndex)
	copy(batchBytes[daBatchV7OffsetBlobVersionedHash:daBatchV7OffsetParentBatchHash], b.blobVersionedHash[:])
	copy(batchBytes[daBatchV7OffsetParentBatchHash:daBatchV7EncodedLength], b.parentBatchHash[:])
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *daBatchV7) Hash() common.Hash {
	return crypto.Keccak256Hash(b.Encode())
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
// Note: This method is not implemented for daBatchV7.
func (b *daBatchV7) BlobDataProofForPointEvaluation() ([]byte, error) {
	return nil, nil
}

// Blob returns the blob of the batch.
func (b *daBatchV7) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *daBatchV7) BlobBytes() []byte {
	return b.blobBytes
}

// MarshalJSON implements the custom JSON serialization for daBatchV7.
// This method is designed to provide prover with batch info in snake_case format.
func (b *daBatchV7) MarshalJSON() ([]byte, error) {
	type daBatchV7JSON struct {
		Version           CodecVersion `json:"version"`
		BatchIndex        uint64       `json:"batch_index"`
		BlobVersionedHash string       `json:"blob_versioned_hash"`
		ParentBatchHash   string       `json:"parent_batch_hash"`
	}

	return json.Marshal(&daBatchV7JSON{
		Version:           b.version,
		BatchIndex:        b.batchIndex,
		BlobVersionedHash: b.blobVersionedHash.Hex(),
		ParentBatchHash:   b.parentBatchHash.Hex(),
	})
}

// Version returns the version of the DABatch.
func (b *daBatchV7) Version() CodecVersion {
	return b.version
}

// SkippedL1MessageBitmap returns the skipped L1 message bitmap of the DABatch.
// For daBatchV7, there is no skipped L1 message bitmap.
func (b *daBatchV7) SkippedL1MessageBitmap() []byte {
	return nil
}

// DataHash returns the data hash of the DABatch.
// For daBatchV7, there is no data hash.
func (b *daBatchV7) DataHash() common.Hash {
	return common.Hash{}
}

type blobPayloadV7 struct {
	initialL1MessageIndex     uint64
	initialL1MessageQueueHash common.Hash
	lastL1MessageQueueHash    common.Hash

	// used for encoding
	blocks []*Block

	// used for decoding
	daBlocks       []DABlock
	l2Transactions []types.Transactions
}

func (b *blobPayloadV7) InitialL1MessageIndex() uint64 {
	return b.initialL1MessageIndex
}
func (b *blobPayloadV7) InitialL1MessageQueueHash() common.Hash {
	return b.initialL1MessageQueueHash
}

func (b *blobPayloadV7) LastL1MessageQueueHash() common.Hash {
	return b.lastL1MessageQueueHash
}

func (b *blobPayloadV7) Blocks() []DABlock {
	return b.daBlocks
}

func (b *blobPayloadV7) Transactions() []types.Transactions {
	return b.l2Transactions
}

func (b *blobPayloadV7) Encode() ([]byte, error) {
	payloadBytes := make([]byte, blobPayloadV7MinEncodedLength)

	binary.BigEndian.PutUint64(payloadBytes[blobPayloadV7OffsetInitialL1MessageIndex:blobPayloadV7OffsetInitialL1MessageQueue], b.initialL1MessageIndex)
	copy(payloadBytes[blobPayloadV7OffsetInitialL1MessageQueue:blobPayloadV7OffsetLastL1MessageQueue], b.initialL1MessageQueueHash[:])
	copy(payloadBytes[blobPayloadV7OffsetLastL1MessageQueue:blobPayloadV7OffsetInitialL2BlockNumber], b.lastL1MessageQueueHash[:])

	var initialL2BlockNumber uint64
	if len(b.blocks) > 0 {
		initialL2BlockNumber = b.blocks[0].Header.Number.Uint64()
		binary.BigEndian.PutUint64(payloadBytes[blobPayloadV7OffsetInitialL2BlockNumber:blobPayloadV7OffsetNumBlocks], initialL2BlockNumber)
	}
	binary.BigEndian.PutUint16(payloadBytes[blobPayloadV7OffsetNumBlocks:blobPayloadV7OffsetBlocks], uint16(len(b.blocks)))

	l1MessageIndex := b.initialL1MessageIndex
	var transactionBytes []byte
	for i, block := range b.blocks {
		// sanity check: block numbers are contiguous
		if block.Header.Number.Uint64() != initialL2BlockNumber+uint64(i) {
			return nil, fmt.Errorf("invalid block number: expected %d but got %d", initialL2BlockNumber+uint64(i), block.Header.Number.Uint64())
		}

		// sanity check (within NumL1MessagesNoSkipping): L1 message indices are contiguous within a block
		numL1Messages, highestQueueIndex, err := block.NumL1MessagesNoSkipping()
		if err != nil {
			return nil, fmt.Errorf("failed to get numL1Messages: %w", err)
		}
		// sanity check: L1 message indices are contiguous across blocks boundaries
		if numL1Messages > 0 {
			if l1MessageIndex+uint64(numL1Messages) != highestQueueIndex+1 {
				return nil, fmt.Errorf("failed to sanity check L1 messages count after block %d: l1MessageIndex + numL1Messages != highestQueueIndex+1: %d + %d != %d", block.Header.Number.Uint64(), l1MessageIndex, numL1Messages, highestQueueIndex+1)
			}
			l1MessageIndex += uint64(numL1Messages)
		}

		daBlock := newDABlockV7(block.Header.Number.Uint64(), block.Header.Time, block.Header.BaseFee, block.Header.GasLimit, uint16(len(block.Transactions)), numL1Messages)
		payloadBytes = append(payloadBytes, daBlock.Encode()...)

		// encode L2 txs as RLP and append to transactionBytes
		for _, txData := range block.Transactions {
			if txData.Type == types.L1MessageTxType {
				continue
			}
			rlpTxData, err := convertTxDataToRLPEncoding(txData)
			if err != nil {
				return nil, fmt.Errorf("failed to convert txData to RLP encoding: %w", err)
			}
			transactionBytes = append(transactionBytes, rlpTxData...)
		}
	}
	payloadBytes = append(payloadBytes, transactionBytes...)

	// sanity check: initialL1MessageQueueHash+apply(L1Messages) = lastL1MessageQueueHash
	computedLastL1MessageQueueHash, err := MessageQueueV2ApplyL1MessagesFromBlocks(b.initialL1MessageQueueHash, b.blocks)
	if err != nil {
		return nil, fmt.Errorf("failed to apply L1 messages to initialL1MessageQueueHash: %w", err)
	}
	if computedLastL1MessageQueueHash != b.lastL1MessageQueueHash {
		return nil, fmt.Errorf("failed to sanity check lastL1MessageQueueHash after applying all L1 messages: expected %s, got %s", computedLastL1MessageQueueHash, b.lastL1MessageQueueHash)
	}

	return payloadBytes, nil
}

func decodeBlobPayloadV7(data []byte) (*blobPayloadV7, error) {
	if len(data) < blobPayloadV7MinEncodedLength {
		return nil, fmt.Errorf("invalid data length for blobPayloadV7, expected at least %d bytes but got %d", blobPayloadV7MinEncodedLength, len(data))
	}

	initialL1MessageIndex := binary.BigEndian.Uint64(data[blobPayloadV7OffsetInitialL1MessageIndex:blobPayloadV7OffsetInitialL1MessageQueue])
	initialL1MessageQueueHash := common.BytesToHash(data[blobPayloadV7OffsetInitialL1MessageQueue:blobPayloadV7OffsetLastL1MessageQueue])
	lastL1MessageQueueHash := common.BytesToHash(data[blobPayloadV7OffsetLastL1MessageQueue:blobPayloadV7OffsetInitialL2BlockNumber])

	initialL2BlockNumber := binary.BigEndian.Uint64(data[blobPayloadV7OffsetInitialL2BlockNumber:blobPayloadV7OffsetNumBlocks])
	numBlocks := int(binary.BigEndian.Uint16(data[blobPayloadV7OffsetNumBlocks:blobPayloadV7OffsetBlocks]))

	if len(data) < blobPayloadV7OffsetBlocks+daBlockV7BlockContextEncodedLength*numBlocks {
		return nil, fmt.Errorf("invalid data length for blobPayloadV7, expected at least %d bytes but got %d", blobPayloadV7OffsetBlocks+daBlockV7BlockContextEncodedLength*numBlocks, len(data))
	}

	// decode DA Blocks from the blob
	daBlocks := make([]DABlock, 0, numBlocks)
	for i := uint64(0); i < uint64(numBlocks); i++ {
		daBlock := newDABlockV7WithNumber(initialL2BlockNumber + i)

		startBytes := blobPayloadV7OffsetBlocks + i*daBlockV7BlockContextEncodedLength
		endBytes := startBytes + daBlockV7BlockContextEncodedLength
		if err := daBlock.Decode(data[startBytes:endBytes]); err != nil {
			return nil, fmt.Errorf("failed to decode DA block: %w", err)
		}

		daBlocks = append(daBlocks, daBlock)
	}

	// decode l2Transactions for each block from the blob
	txBytes := data[blobPayloadV7OffsetBlocks+daBlockV7BlockContextEncodedLength*numBlocks:]
	curIndex := 0
	var transactions []types.Transactions

	for _, daBlock := range daBlocks {
		var blockTransactions types.Transactions
		txNum := int(daBlock.NumTransactions()) - int(daBlock.NumL1Messages())
		if txNum < 0 {
			return nil, fmt.Errorf("invalid transaction count: NumL1Messages (%d) exceeds NumTransactions (%d)", daBlock.NumL1Messages(), daBlock.NumTransactions())
		}

		for i := 0; i < txNum; i++ {
			tx, nextIndex, err := getNextTx(txBytes, curIndex)
			if err != nil {
				return nil, fmt.Errorf("couldn't decode next tx from blob bytes: %w, index: %d", err, curIndex+4)
			}
			curIndex = nextIndex
			blockTransactions = append(blockTransactions, tx)
		}

		transactions = append(transactions, blockTransactions)
	}

	return &blobPayloadV7{
		initialL1MessageIndex:     initialL1MessageIndex,
		initialL1MessageQueueHash: initialL1MessageQueueHash,
		lastL1MessageQueueHash:    lastL1MessageQueueHash,
		daBlocks:                  daBlocks,
		l2Transactions:            transactions,
	}, nil
}

type daBlockV7 struct {
	daBlockV0
}

// newDABlockV7 is a constructor function for daBlockV7 that initializes the internal fields.
func newDABlockV7(number uint64, timestamp uint64, baseFee *big.Int, gasLimit uint64, numTransactions uint16, numL1Messages uint16) *daBlockV7 {
	return &daBlockV7{
		daBlockV0: daBlockV0{
			number:          number,
			timestamp:       timestamp,
			baseFee:         baseFee,
			gasLimit:        gasLimit,
			numTransactions: numTransactions,
			numL1Messages:   numL1Messages,
		},
	}
}

func newDABlockV7WithNumber(number uint64) *daBlockV7 {
	return &daBlockV7{
		daBlockV0: daBlockV0{
			number: number,
		},
	}
}

// Encode serializes the DABlock into a slice of bytes.
func (b *daBlockV7) Encode() []byte {
	daBlockBytes := make([]byte, daBlockV7BlockContextEncodedLength)
	binary.BigEndian.PutUint64(daBlockBytes[daBlockV7OffsetTimestamp:daBlockV7OffsetBaseFee], b.timestamp)
	if b.baseFee != nil {
		b.baseFee.FillBytes(daBlockBytes[daBlockV7OffsetBaseFee:daBlockV7OffsetGasLimit])
	}
	binary.BigEndian.PutUint64(daBlockBytes[daBlockV7OffsetGasLimit:daBlockV7OffsetNumTransactions], b.gasLimit)
	binary.BigEndian.PutUint16(daBlockBytes[daBlockV7OffsetNumTransactions:daBlockV7OffsetNumL1Messages], b.numTransactions)
	binary.BigEndian.PutUint16(daBlockBytes[daBlockV7OffsetNumL1Messages:], b.numL1Messages)
	return daBlockBytes
}

// Decode populates the fields of a DABlock from a byte slice.
func (b *daBlockV7) Decode(data []byte) error {
	if len(data) != daBlockV7BlockContextEncodedLength {
		return fmt.Errorf("block encoding is not blockContextByteSize bytes long expected %d, got %d", daBlockV7BlockContextEncodedLength, len(data))
	}

	b.timestamp = binary.BigEndian.Uint64(data[daBlockV7OffsetTimestamp:daBlockV7OffsetBaseFee])
	b.baseFee = new(big.Int).SetBytes(data[daBlockV7OffsetBaseFee:daBlockV7OffsetGasLimit])
	b.gasLimit = binary.BigEndian.Uint64(data[daBlockV7OffsetGasLimit:daBlockV7OffsetNumTransactions])
	b.numTransactions = binary.BigEndian.Uint16(data[daBlockV7OffsetNumTransactions:daBlockV7OffsetNumL1Messages])
	b.numL1Messages = binary.BigEndian.Uint16(data[daBlockV7OffsetNumL1Messages:])

	return nil
}

// daChunkV7 groups consecutive DABlocks with their transactions.
// Note: In DACodecV7 there is no notion of chunks. Blobs contain the entire batch data without any information of Chunks within.
// However, for compatibility reasons DAChunks are still used in the codebase.
// This way we can still uniquely identify a set of blocks and their L1 messages via their hash.
type daChunkV7 struct {
	daChunkV1
}

// newDAChunkV1 is a constructor for daChunkV1, initializing with blocks and transactions.
func newDAChunkV7(blocks []DABlock, transactions [][]*types.TransactionData) *daChunkV7 {
	return &daChunkV7{
		daChunkV1{
			blocks:       blocks,
			transactions: transactions,
		},
	}
}

// Hash computes the hash of the DAChunk data.
func (c *daChunkV7) Hash() (common.Hash, error) {
	var dataBytes []byte

	// concatenate block contexts
	for _, block := range c.blocks {
		encodedBlock := block.Encode()
		dataBytes = append(dataBytes, encodedBlock...)
	}

	// concatenate l1 tx hashes
	for _, blockTxs := range c.transactions {
		for _, txData := range blockTxs {
			if txData.Type != types.L1MessageTxType {
				continue
			}

			hashBytes := common.FromHex(txData.TxHash)
			if len(hashBytes) != common.HashLength {
				return common.Hash{}, fmt.Errorf("unexpected hash: %s", txData.TxHash)
			}
			dataBytes = append(dataBytes, hashBytes...)
		}
	}

	hash := crypto.Keccak256Hash(dataBytes)
	return hash, nil
}

// decompressV7Bytes decompresses the given blob bytes into the original payload bytes.
func decompressV7Bytes(compressedBytes []byte) ([]byte, error) {
	var res []byte

	compressedBytes = append(zstdMagicNumber, compressedBytes...)
	r := bytes.NewReader(compressedBytes)
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd reader: %w", err)
	}
	defer zr.Close()

	res, err = zr.DecodeAll(compressedBytes, res)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress zstd data: %w", err)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("payload is empty after decompression")
	}

	return res, nil
}

func decodeSize3Bytes(data []byte) uint32 {
	return uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
}

func encodeSize3Bytes(data uint32) []byte {
	return []byte{byte(data >> 16), byte(data >> 8), byte(data)}
}
