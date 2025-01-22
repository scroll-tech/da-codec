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

const (
	daBatchV7EncodedLength           = 73
	daBatchV7OffsetBlobVersionedHash = 9
	daBatchV7OffsetParentBatchHash   = 41
)

const (
	blobEnvelopeV7VersionOffset        = 0
	blobEnvelopeV7ByteSizeOffset       = 1
	blobEnvelopeV7CompressedFlagOffset = 4
	blobEnvelopeV7PayloadOffset        = 5
)

const (
	blobPayloadV7EncodedLength               = 8 + 2*common.HashLength + 8 + 2
	blobPayloadV7OffsetInitialL1MessageIndex = 0
	blobPayloadV7OffsetInitialL1MessageQueue = blobPayloadV7OffsetInitialL1MessageIndex + 8
	blobPayloadV7OffsetLastL1MessageQueue    = blobPayloadV7OffsetInitialL1MessageQueue + common.HashLength
	blobPayloadV7OffsetInitialL2BlockNumber  = blobPayloadV7OffsetLastL1MessageQueue + common.HashLength
	blobPayloadV7OffsetNumBlocks             = blobPayloadV7OffsetInitialL2BlockNumber + 8
	blobPayloadV7OffsetBlocks                = blobPayloadV7OffsetNumBlocks + 2
)

const (
	daBlockV7BlockContextByteSize  = 52
	daBlockV7OffsetTimestamp       = 0
	daBlockV7OffsetBaseFee         = daBlockV7OffsetTimestamp + 8
	daBlockV7OffsetGasLimit        = daBlockV7OffsetBaseFee + 32
	daBlockV7numTransactionsOffset = daBlockV7OffsetGasLimit + 8
	daBlockV7numL1MessagesOffset   = daBlockV7numTransactionsOffset + 2
)

// daBatchV3 contains metadata about a batch of DAChunks.
type daBatchV7 struct {
	version           CodecVersion
	batchIndex        uint64
	blobVersionedHash common.Hash
	parentBatchHash   common.Hash

	blob      *kzg4844.Blob
	blobBytes []byte
}

// newDABatchV7 is a constructor for daBatchV7 that calls blobDataProofForPICircuit internally.
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

// Encode serializes the DABatchV3 into bytes.
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

// MarshalJSON implements the custom JSON serialization for daBatchV3.
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
	daBlocks     []DABlock
	transactions []types.Transactions
}

func (b *blobPayloadV7) Blocks() []DABlock {
	return b.daBlocks
}

func (b *blobPayloadV7) Transactions() []types.Transactions {
	return b.transactions
}

func (b *blobPayloadV7) InitialL1MessageIndex() uint64 {
	return b.initialL1MessageIndex
}

func (b *blobPayloadV7) Encode() ([]byte, error) {
	payloadBytes := make([]byte, blobPayloadV7EncodedLength)

	binary.BigEndian.PutUint64(payloadBytes[blobPayloadV7OffsetInitialL1MessageIndex:blobPayloadV7OffsetInitialL1MessageQueue], b.initialL1MessageIndex)
	copy(payloadBytes[blobPayloadV7OffsetInitialL1MessageQueue:blobPayloadV7OffsetLastL1MessageQueue], b.initialL1MessageQueueHash[:])
	copy(payloadBytes[blobPayloadV7OffsetLastL1MessageQueue:blobPayloadV7OffsetInitialL2BlockNumber], b.lastL1MessageQueueHash[:])

	blockNumber := b.blocks[0].Header.Number.Uint64()
	binary.BigEndian.PutUint64(payloadBytes[blobPayloadV7OffsetInitialL2BlockNumber:blobPayloadV7OffsetNumBlocks], blockNumber)
	binary.BigEndian.PutUint16(payloadBytes[blobPayloadV7OffsetNumBlocks:blobPayloadV7OffsetBlocks], uint16(len(b.blocks)))

	var transactionBytes []byte
	for _, block := range b.blocks {
		daBlock := newDABlockV7(block.Header.Number.Uint64(), block.Header.Time, block.Header.BaseFee, block.Header.GasLimit, uint16(len(block.Transactions)), block.NumL1MessagesNoSkipping())
		payloadBytes = append(payloadBytes, daBlock.Encode()...)

		// encode L2 txs as RLP and append to transactionBytes
		for _, tx := range block.Transactions {
			if tx.Type == types.L1MessageTxType {
				continue
			}

			rlpTxData, err := convertTxDataToRLPEncoding(tx)
			if err != nil {
				return nil, fmt.Errorf("failed to convert txData to RLP encoding: %w", err)
			}
			transactionBytes = append(transactionBytes, rlpTxData...)
		}
	}
	payloadBytes = append(payloadBytes, transactionBytes...)

	return payloadBytes, nil
}

func decodeBlobPayloadV7(data []byte) (*blobPayloadV7, error) {
	if len(data) < blobPayloadV7EncodedLength {
		return nil, fmt.Errorf("invalid data length for blobPayloadV7, expected at least %d bytes but got %d", blobPayloadV7EncodedLength, len(data))
	}

	initialL1MessageIndex := binary.BigEndian.Uint64(data[blobPayloadV7OffsetInitialL1MessageIndex:blobPayloadV7OffsetInitialL1MessageQueue])
	initialL1MessageQueueHash := common.BytesToHash(data[blobPayloadV7OffsetInitialL1MessageQueue:blobPayloadV7OffsetLastL1MessageQueue])
	lastL1MessageQueueHash := common.BytesToHash(data[blobPayloadV7OffsetLastL1MessageQueue:blobPayloadV7OffsetInitialL2BlockNumber])

	initialL2BlockNumber := binary.BigEndian.Uint64(data[blobPayloadV7OffsetInitialL2BlockNumber:blobPayloadV7OffsetNumBlocks])
	numBlocks := int(binary.BigEndian.Uint16(data[blobPayloadV7OffsetNumBlocks:blobPayloadV7OffsetBlocks]))

	// decode DA Blocks from the blob
	daBlocks := make([]DABlock, numBlocks)
	for i := uint64(0); i < uint64(numBlocks); i++ {
		daBlock := newDABlockV7WithNumber(initialL2BlockNumber + i)

		startBytes := blobPayloadV7OffsetBlocks + i*daBlockV7BlockContextByteSize
		endBytes := startBytes + daBlockV7BlockContextByteSize
		if err := daBlock.Decode(data[startBytes:endBytes]); err != nil {
			return nil, fmt.Errorf("failed to decode DA block: %w", err)
		}

		daBlocks = append(daBlocks, daBlock)
	}

	// decode transactions for each block from the blob
	txBytes := data[blobPayloadV7OffsetBlocks+daBlockV7BlockContextByteSize*numBlocks:]
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
		transactions:              transactions,
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
	daBlockBytes := make([]byte, daBlockV7BlockContextByteSize)
	binary.BigEndian.PutUint64(daBlockBytes[daBlockV7OffsetTimestamp:daBlockV7OffsetBaseFee], b.timestamp)
	if b.baseFee != nil {
		b.baseFee.FillBytes(daBlockBytes[daBlockV7OffsetBaseFee:daBlockV7OffsetGasLimit])
	}
	binary.BigEndian.PutUint64(daBlockBytes[daBlockV7OffsetGasLimit:daBlockV7numTransactionsOffset], b.gasLimit)
	binary.BigEndian.PutUint16(daBlockBytes[daBlockV7numTransactionsOffset:daBlockV7numL1MessagesOffset], b.numTransactions)
	binary.BigEndian.PutUint16(daBlockBytes[daBlockV7numL1MessagesOffset:], b.numL1Messages)
	return daBlockBytes
}

// Decode populates the fields of a DABlock from a byte slice.
func (b *daBlockV7) Decode(data []byte) error {
	if len(data) != daBlockV7BlockContextByteSize {
		return fmt.Errorf("block encoding is not blockContextByteSize bytes long expected %d, got %d", daBlockV7BlockContextByteSize, len(data))
	}

	b.timestamp = binary.BigEndian.Uint64(data[daBlockV7OffsetTimestamp:daBlockV7OffsetBaseFee])
	b.baseFee = new(big.Int).SetBytes(data[daBlockV7OffsetBaseFee:daBlockV7OffsetGasLimit])
	b.gasLimit = binary.BigEndian.Uint64(data[daBlockV7OffsetGasLimit:daBlockV7numTransactionsOffset])
	b.numTransactions = binary.BigEndian.Uint16(data[daBlockV7numTransactionsOffset:daBlockV7numL1MessagesOffset])
	b.numL1Messages = binary.BigEndian.Uint16(data[daBlockV7numL1MessagesOffset:])

	return nil
}

// decompressV7Bytes decompresses the given blob bytes into the original payload bytes.
func decompressV7Bytes(compressedBytes []byte) ([]byte, error) {
	var res []byte

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
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
}

func encodeSize3Bytes(data uint32) []byte {
	return []byte{byte(data), byte(data >> 8), byte(data >> 16)}
}
