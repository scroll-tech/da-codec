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
	blobEnvelopeV7VersionOffset        = 0
	blobEnvelopeV7ByteSizeOffset       = 1
	blobEnvelopeV7CompressedFlagOffset = 4
	blobEnvelopeV7PayloadOffset        = 5
)

const (
	blobPayloadV6EncodedLength               = 8 + 2*common.HashLength + 8 + 2
	blobPayloadV6OffsetInitialL1MessageIndex = 0
	blobPayloadV6OffsetInitialL1MessageQueue = blobPayloadV6OffsetInitialL1MessageIndex + 8
	blobPayloadV6OffsetLastL1MessageQueue    = blobPayloadV6OffsetInitialL1MessageQueue + common.HashLength
	blobPayloadV6OffsetInitialL2BlockNumber  = blobPayloadV6OffsetLastL1MessageQueue + common.HashLength
	blobPayloadV6OffsetNumBlocks             = blobPayloadV6OffsetInitialL2BlockNumber + 8
	blobPayloadV6OffsetBlocks                = blobPayloadV6OffsetNumBlocks + 2
)

const (
	daBlockV6BlockContextByteSize  = 52
	daBlockV6OffsetTimestamp       = 0
	daBlockV6OffsetBaseFee         = daBlockV6OffsetTimestamp + 8
	daBlockV6OffsetGasLimit        = daBlockV6OffsetBaseFee + 32
	daBlockV6numTransactionsOffset = daBlockV6OffsetGasLimit + 8
	daBlockV6numL1MessagesOffset   = daBlockV6numTransactionsOffset + 2
)

// daBatchV3 contains metadata about a batch of DAChunks.
type daBatchV6 struct {
	version           CodecVersion
	batchIndex        uint64
	parentBatchHash   common.Hash
	blobVersionedHash common.Hash

	blob      *kzg4844.Blob
	blobBytes []byte
}

// newDABatchV6 is a constructor for daBatchV6 that calls blobDataProofForPICircuit internally.
func newDABatchV6(version CodecVersion, batchIndex uint64, parentBatchHash, blobVersionedHash common.Hash, blob *kzg4844.Blob, blobBytes []byte) (*daBatchV6, error) {
	daBatch := &daBatchV6{
		version:           version,
		batchIndex:        batchIndex,
		parentBatchHash:   parentBatchHash,
		blobVersionedHash: blobVersionedHash,
		blob:              blob,
		blobBytes:         blobBytes,
	}

	return daBatch, nil
}

func decodeDABatchV6(data []byte) (*daBatchV6, error) {
	if len(data) != daBatchV6EncodedLength {
		return nil, fmt.Errorf("invalid data length for DABatchV6, expected %d bytes but got %d", daBatchV6EncodedLength, len(data))
	}

	version := CodecVersion(data[daBatchOffsetVersion])
	batchIndex := binary.BigEndian.Uint64(data[daBatchOffsetBatchIndex:daBatchV6OffsetBlobVersionedHash])
	blobVersionedHash := common.BytesToHash(data[daBatchV6OffsetBlobVersionedHash:daBatchV6OffsetParentBatchHash])
	parentBatchHash := common.BytesToHash(data[daBatchV6OffsetParentBatchHash:daBatchV6EncodedLength])

	return newDABatchV6(version, batchIndex, parentBatchHash, blobVersionedHash, nil, nil)
}

// Encode serializes the DABatchV3 into bytes.
func (b *daBatchV6) Encode() []byte {
	batchBytes := make([]byte, daBatchV6EncodedLength)
	batchBytes[daBatchOffsetVersion] = byte(b.version)
	binary.BigEndian.PutUint64(batchBytes[daBatchOffsetBatchIndex:daBatchV6OffsetBlobVersionedHash], b.batchIndex)
	copy(batchBytes[daBatchV6OffsetBlobVersionedHash:daBatchV6OffsetParentBatchHash], b.blobVersionedHash[:])
	copy(batchBytes[daBatchV6OffsetParentBatchHash:daBatchV6EncodedLength], b.parentBatchHash[:])
	return batchBytes
}

// Hash computes the hash of the serialized DABatch.
func (b *daBatchV6) Hash() common.Hash {
	return crypto.Keccak256Hash(b.Encode())
}

// BlobDataProofForPointEvaluation computes the abi-encoded blob verification data.
// Note: This method is not implemented for daBatchV6.
func (b *daBatchV6) BlobDataProofForPointEvaluation() ([]byte, error) {
	return nil, nil
}

// Blob returns the blob of the batch.
func (b *daBatchV6) Blob() *kzg4844.Blob {
	return b.blob
}

// BlobBytes returns the blob bytes of the batch.
func (b *daBatchV6) BlobBytes() []byte {
	return b.blobBytes
}

// MarshalJSON implements the custom JSON serialization for daBatchV3.
// This method is designed to provide prover with batch info in snake_case format.
func (b *daBatchV6) MarshalJSON() ([]byte, error) {
	type daBatchV6JSON struct {
		Version           CodecVersion `json:"version"`
		BatchIndex        uint64       `json:"batch_index"`
		BlobVersionedHash string       `json:"blob_versioned_hash"`
		ParentBatchHash   string       `json:"parent_batch_hash"`
	}

	return json.Marshal(&daBatchV6JSON{
		Version:           b.version,
		BatchIndex:        b.batchIndex,
		BlobVersionedHash: b.blobVersionedHash.Hex(),
		ParentBatchHash:   b.parentBatchHash.Hex(),
	})
}

// Version returns the version of the DABatch.
func (b *daBatchV6) Version() CodecVersion {
	return b.version
}

// SkippedL1MessageBitmap returns the skipped L1 message bitmap of the DABatch.
// For daBatchV6, there is no skipped L1 message bitmap.
func (b *daBatchV6) SkippedL1MessageBitmap() []byte {
	return nil
}

// DataHash returns the data hash of the DABatch.
// For daBatchV6, there is no data hash.
func (b *daBatchV6) DataHash() common.Hash {
	return common.Hash{}
}

type blobPayloadV6 struct {
	initialL1MessageIndex     uint64
	initialL1MessageQueueHash common.Hash
	lastL1MessageQueueHash    common.Hash

	// used for encoding
	blocks []*Block

	// used for decoding
	daBlocks     []DABlock
	transactions []types.Transactions
}

func (b *blobPayloadV6) Encode() ([]byte, error) {
	payloadBytes := make([]byte, blobPayloadV6EncodedLength)

	binary.BigEndian.PutUint64(payloadBytes[blobPayloadV6OffsetInitialL1MessageIndex:blobPayloadV6OffsetInitialL1MessageQueue], b.initialL1MessageIndex)
	copy(payloadBytes[blobPayloadV6OffsetInitialL1MessageQueue:blobPayloadV6OffsetLastL1MessageQueue], b.initialL1MessageQueueHash[:])
	copy(payloadBytes[blobPayloadV6OffsetLastL1MessageQueue:blobPayloadV6OffsetInitialL2BlockNumber], b.lastL1MessageQueueHash[:])

	blockNumber := b.blocks[0].Header.Number.Uint64()
	binary.BigEndian.PutUint64(payloadBytes[blobPayloadV6OffsetInitialL2BlockNumber:blobPayloadV6OffsetNumBlocks], blockNumber)
	binary.BigEndian.PutUint16(payloadBytes[blobPayloadV6OffsetNumBlocks:blobPayloadV6OffsetBlocks], uint16(len(b.blocks)))

	var transactionBytes []byte
	for _, block := range b.blocks {
		daBlock := newDABlockV6(block.Header.Number.Uint64(), block.Header.Time, block.Header.BaseFee, block.Header.GasLimit, uint16(len(block.Transactions)), block.NumL1MessagesNoSkipping())
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

func decodeBlobPayloadV6(data []byte) (*blobPayloadV6, error) {
	if len(data) < blobPayloadV6EncodedLength {
		return nil, fmt.Errorf("invalid data length for blobPayloadV6, expected at least %d bytes but got %d", blobPayloadV6EncodedLength, len(data))
	}

	initialL1MessageIndex := binary.BigEndian.Uint64(data[blobPayloadV6OffsetInitialL1MessageIndex:blobPayloadV6OffsetInitialL1MessageQueue])
	initialL1MessageQueueHash := common.BytesToHash(data[blobPayloadV6OffsetInitialL1MessageQueue:blobPayloadV6OffsetLastL1MessageQueue])
	lastL1MessageQueueHash := common.BytesToHash(data[blobPayloadV6OffsetLastL1MessageQueue:blobPayloadV6OffsetInitialL2BlockNumber])

	initialL2BlockNumber := binary.BigEndian.Uint64(data[blobPayloadV6OffsetInitialL2BlockNumber:blobPayloadV6OffsetNumBlocks])
	numBlocks := int(binary.BigEndian.Uint16(data[blobPayloadV6OffsetNumBlocks:blobPayloadV6OffsetBlocks]))

	// decode DA Blocks from the blob
	daBlocks := make([]DABlock, numBlocks)
	for i := uint64(0); i < uint64(numBlocks); i++ {
		daBlock := newDABlockV6WithNumber(initialL2BlockNumber + i)

		startBytes := blobPayloadV6OffsetBlocks + i*daBlockV6BlockContextByteSize
		endBytes := startBytes + daBlockV6BlockContextByteSize
		if err := daBlock.Decode(data[startBytes:endBytes]); err != nil {
			return nil, fmt.Errorf("failed to decode DA block: %w", err)
		}

		daBlocks = append(daBlocks, daBlock)
	}

	// decode transactions for each block from the blob
	txBytes := data[blobPayloadV6OffsetBlocks+daBlockV6BlockContextByteSize*numBlocks:]
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

	return &blobPayloadV6{
		initialL1MessageIndex:     initialL1MessageIndex,
		initialL1MessageQueueHash: initialL1MessageQueueHash,
		lastL1MessageQueueHash:    lastL1MessageQueueHash,
		daBlocks:                  daBlocks,
		transactions:              transactions,
	}, nil
}

type daBlockV6 struct {
	daBlockV0
}

// newDABlockV6 is a constructor function for daBlockV6 that initializes the internal fields.
func newDABlockV6(number uint64, timestamp uint64, baseFee *big.Int, gasLimit uint64, numTransactions uint16, numL1Messages uint16) *daBlockV6 {
	return &daBlockV6{
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

func newDABlockV6WithNumber(number uint64) *daBlockV6 {
	return &daBlockV6{
		daBlockV0: daBlockV0{
			number: number,
		},
	}
}

// Encode serializes the DABlock into a slice of bytes.
func (b *daBlockV6) Encode() []byte {
	daBlockBytes := make([]byte, daBlockV6BlockContextByteSize)
	binary.BigEndian.PutUint64(daBlockBytes[daBlockV6OffsetTimestamp:daBlockV6OffsetBaseFee], b.timestamp)
	if b.baseFee != nil {
		b.baseFee.FillBytes(daBlockBytes[daBlockV6OffsetBaseFee:daBlockV6OffsetGasLimit])
	}
	binary.BigEndian.PutUint64(daBlockBytes[daBlockV6OffsetGasLimit:daBlockV6numTransactionsOffset], b.gasLimit)
	binary.BigEndian.PutUint16(daBlockBytes[daBlockV6numTransactionsOffset:daBlockV6numL1MessagesOffset], b.numTransactions)
	binary.BigEndian.PutUint16(daBlockBytes[daBlockV6numL1MessagesOffset:], b.numL1Messages)
	return daBlockBytes
}

// Decode populates the fields of a DABlock from a byte slice.
func (b *daBlockV6) Decode(data []byte) error {
	if len(data) != daBlockV6BlockContextByteSize {
		return fmt.Errorf("block encoding is not blockContextByteSize bytes long expected %d, got %d", daBlockV6BlockContextByteSize, len(data))
	}

	b.timestamp = binary.BigEndian.Uint64(data[daBlockV6OffsetTimestamp:daBlockV6OffsetBaseFee])
	b.baseFee = new(big.Int).SetBytes(data[daBlockV6OffsetBaseFee:daBlockV6OffsetGasLimit])
	b.gasLimit = binary.BigEndian.Uint64(data[daBlockV6OffsetGasLimit:daBlockV6numTransactionsOffset])
	b.numTransactions = binary.BigEndian.Uint16(data[daBlockV6numTransactionsOffset:daBlockV6numL1MessagesOffset])
	b.numL1Messages = binary.BigEndian.Uint16(data[daBlockV6numL1MessagesOffset:])

	return nil
}

// decompressV6Bytes decompresses the given blob bytes into the original payload bytes.
func decompressV6Bytes(compressedBytes []byte) ([]byte, error) {
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
