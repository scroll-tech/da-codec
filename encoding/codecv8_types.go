package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
)

// Below is the encoding for DABlockV8, variable length 5-57 bytes.
// Delta encoding is used for efficiency with escape sequences for full values.
//   * Field                   Bytes              Type                     Index  Comments
//   * timestamp               1[+8]              uint8[+uint64]           0      Delta encoded, 0xFF escape → uint64 full value
//   * baseFee                 1[+1|2|3|4|8|32]   uint8[+int8-64|uint256]  1      Delta encoded with dynamic length, 0xFF escape → uint256 full value
//   * gasLimit                1[+8]              uint8[+uint64]           N      Delta encoded, 0xFF escape → uint64 full value
//   * numTransactions         1[+2]              uint8[+uint16]           N+1    Total value, 0xFF escape → uint16
//   * numL1Messages           1[+2]              uint8[+uint16]           N+2    Total value, 0xFF escape → uint16

const (
	// Escape value for delta encoding
	deltaEscapeValue = 0xFF

	// BaseFee delta encoding types
	baseFeeNoValue = 0
	baseFeeDelta8  = 1
	baseFeeDelta16 = 2
	baseFeeDelta24 = 3
	baseFeeDelta32 = 4
	baseFeeDelta64 = 8
	baseFeeEscape  = 0xFF
)

// daBatchV8 contains V8 batch metadata and payload.
type daBatchV8 struct {
	*daBatchV7
}

func newDABatchV8(version CodecVersion, batchIndex uint64, blobVersionedHash, parentBatchHash common.Hash, blob *kzg4844.Blob, blobBytes []byte, challengeDigest common.Hash) (*daBatchV8, error) {
	v7Batch, err := newDABatchV7(version, batchIndex, blobVersionedHash, parentBatchHash, blob, blobBytes, challengeDigest)
	if err != nil {
		return nil, err
	}
	return &daBatchV8{daBatchV7: v7Batch}, nil
}

func decodeDABatchV8(data []byte) (*daBatchV8, error) {
	v7Batch, err := decodeDABatchV7(data)
	if err != nil {
		return nil, err
	}
	return &daBatchV8{daBatchV7: v7Batch}, nil
}

type blobPayloadV8 struct {
	*blobPayloadV7
}

// Encode serializes the blobPayloadV8 into bytes using delta encoding for blocks.
func (b *blobPayloadV8) Encode() ([]byte, error) {
	payloadBytes := make([]byte, blobPayloadV7MinEncodedLength)

	copy(payloadBytes[blobPayloadV7OffsetPrevL1MessageQueue:blobPayloadV7OffsetPostL1MessageQueue], b.prevL1MessageQueueHash[:])
	copy(payloadBytes[blobPayloadV7OffsetPostL1MessageQueue:blobPayloadV7OffsetInitialL2BlockNumber], b.postL1MessageQueueHash[:])

	var transactionBytes []byte
	var previousBlock *daBlockV8

	if err := iterateAndVerifyBlocksAndL1MessagesV8(b.prevL1MessageQueueHash, b.postL1MessageQueueHash, b.blocks, nil, func(initialL2BlockNumber uint64) {
		binary.BigEndian.PutUint64(payloadBytes[blobPayloadV7OffsetInitialL2BlockNumber:blobPayloadV7OffsetNumBlocks], initialL2BlockNumber)
		binary.BigEndian.PutUint16(payloadBytes[blobPayloadV7OffsetNumBlocks:blobPayloadV7OffsetBlocks], uint16(len(b.blocks)))
	}, func(block *Block, daBlock *daBlockV8) error {
		encodedBlock := daBlock.encodeWithDelta(previousBlock)
		payloadBytes = append(payloadBytes, encodedBlock...)
		previousBlock = daBlock

		// encode L2 txs as RLP and append to transactionBytes
		for _, txData := range block.Transactions {
			if txData.Type == types.L1MessageTxType {
				continue
			}
			rlpTxData, err := convertTxDataToRLPEncoding(txData)
			if err != nil {
				return fmt.Errorf("failed to convert txData to RLP encoding: %w", err)
			}
			transactionBytes = append(transactionBytes, rlpTxData...)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to iterate and verify blocks and L1 messages: %w", err)
	}

	payloadBytes = append(payloadBytes, transactionBytes...)

	return payloadBytes, nil
}

func decodeBlobPayloadV8(data []byte) (*blobPayloadV8, error) {
	if len(data) < blobPayloadV7MinEncodedLength {
		return nil, fmt.Errorf("invalid data length for blobPayloadV8, expected at least %d bytes but got %d", blobPayloadV7MinEncodedLength, len(data))
	}

	prevL1MessageQueueHash := common.BytesToHash(data[blobPayloadV7OffsetPrevL1MessageQueue:blobPayloadV7OffsetPostL1MessageQueue])
	postL1MessageQueueHash := common.BytesToHash(data[blobPayloadV7OffsetPostL1MessageQueue:blobPayloadV7OffsetInitialL2BlockNumber])

	initialL2BlockNumber := binary.BigEndian.Uint64(data[blobPayloadV7OffsetInitialL2BlockNumber:blobPayloadV7OffsetNumBlocks])
	numBlocks := int(binary.BigEndian.Uint16(data[blobPayloadV7OffsetNumBlocks:blobPayloadV7OffsetBlocks]))

	// decode DA Blocks from the blob with variable length encoding
	daBlocks := make([]DABlock, 0, numBlocks)
	offset := blobPayloadV7OffsetBlocks
	var previousBlock *daBlockV8

	for i := 0; i < numBlocks; i++ {
		daBlock := newDABlockV8WithNumber(initialL2BlockNumber + uint64(i))

		bytesRead, err := daBlock.decodeWithDelta(data[offset:], previousBlock)
		if err != nil {
			return nil, fmt.Errorf("failed to decode DA block %d: %w", i, err)
		}
		offset += bytesRead
		previousBlock = daBlock

		daBlocks = append(daBlocks, daBlock)
	}

	// decode l2Transactions for each block from the blob
	txBytes := data[offset:]
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

	return &blobPayloadV8{blobPayloadV7: &blobPayloadV7{
		prevL1MessageQueueHash: prevL1MessageQueueHash,
		postL1MessageQueueHash: postL1MessageQueueHash,
		daBlocks:               daBlocks,
		l2Transactions:         transactions,
	}}, nil
}

type daBlockV8 struct {
	*daBlockV7
}

func newDABlockV8FromBlockWithValidation(block *Block, totalL1MessagePoppedBefore *uint64) (*daBlockV8, error) {
	v7Block, err := newDABlockV7FromBlockWithValidation(block, totalL1MessagePoppedBefore)
	if err != nil {
		return nil, err
	}
	return &daBlockV8{daBlockV7: v7Block}, nil
}

func newDABlockV8WithNumber(number uint64) *daBlockV8 {
	return &daBlockV8{
		daBlockV7: newDABlockV7WithNumber(number),
	}
}

// encodeWithDelta serializes the DABlock into a slice of bytes using delta encoding.
func (b *daBlockV8) encodeWithDelta(previousBlock *daBlockV8) []byte {
	var result []byte

	// First block in batch - use escape values and full encoding
	if previousBlock == nil {
		// Encode timestamp with escape value
		result = append(result, deltaEscapeValue)
		timestampBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(timestampBytes, b.timestamp)
		result = append(result, timestampBytes...)

		// Encode baseFee with escape value
		result = append(result, baseFeeEscape)
		if b.baseFee != nil {
			baseFeeBytes := make([]byte, 32)
			b.baseFee.FillBytes(baseFeeBytes)
			result = append(result, baseFeeBytes...)
		} else {
			result = append(result, make([]byte, 32)...)
		}

		// Encode gasLimit with escape value
		result = append(result, deltaEscapeValue)
		gasLimitBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(gasLimitBytes, b.gasLimit)
		result = append(result, gasLimitBytes...)

		// Encode numTransactions
		if b.numTransactions < 255 {
			result = append(result, byte(b.numTransactions))
		} else {
			result = append(result, deltaEscapeValue)
			numTxBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(numTxBytes, b.numTransactions)
			result = append(result, numTxBytes...)
		}

		// Encode numL1Messages
		if b.numL1Messages < 255 {
			result = append(result, byte(b.numL1Messages))
		} else {
			result = append(result, deltaEscapeValue)
			numL1MsgBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(numL1MsgBytes, b.numL1Messages)
			result = append(result, numL1MsgBytes...)
		}

		return result
	}

	// Delta encoding for subsequent blocks
	// Encode timestamp with delta
	timestampDelta := int64(b.timestamp) - int64(previousBlock.timestamp)
	if timestampDelta < 255 {
		result = append(result, byte(timestampDelta))
	} else {
		result = append(result, deltaEscapeValue)
		timestampBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(timestampBytes, b.timestamp)
		result = append(result, timestampBytes...)
	}

	// Encode baseFee with delta
	result = append(result, b.encodeBaseFeeDelta(previousBlock)...)

	// Encode gasLimit with delta
	gasLimitDelta := int64(b.gasLimit) - int64(previousBlock.gasLimit)
	if gasLimitDelta >= -128 && gasLimitDelta <= 127 && gasLimitDelta != -1 {
		result = append(result, byte(gasLimitDelta))
	} else {
		result = append(result, deltaEscapeValue)
		gasLimitBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(gasLimitBytes, b.gasLimit)
		result = append(result, gasLimitBytes...)
	}

	// Encode numTransactions (no delta encoding)
	if b.numTransactions < 255 {
		result = append(result, byte(b.numTransactions))
	} else {
		result = append(result, deltaEscapeValue)
		numTxBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(numTxBytes, b.numTransactions)
		result = append(result, numTxBytes...)
	}

	// Encode numL1Messages (no delta encoding)
	if b.numL1Messages < 255 {
		result = append(result, byte(b.numL1Messages))
	} else {
		result = append(result, deltaEscapeValue)
		numL1MsgBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(numL1MsgBytes, b.numL1Messages)
		result = append(result, numL1MsgBytes...)
	}

	return result
}

// encodeBaseFeeDelta encodes the base fee delta using variable-length encoding.
// previousBlock and baseFee fields are not nil when this function is called.
func (b *daBlockV8) encodeBaseFeeDelta(previousBlock *daBlockV8) []byte {
	delta := new(big.Int).Sub(b.baseFee, previousBlock.baseFee)

	if delta.IsInt64() {
		deltaInt64 := delta.Int64()
		if deltaInt64 >= -128 && deltaInt64 <= 127 {
			return []byte{baseFeeDelta8, byte(deltaInt64)}
		} else if deltaInt64 >= -32768 && deltaInt64 <= 32767 {
			result := []byte{baseFeeDelta16}
			deltaBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(deltaBytes, uint16(deltaInt64))
			return append(result, deltaBytes...)
		} else if deltaInt64 >= -8388608 && deltaInt64 <= 8388607 {
			result := []byte{baseFeeDelta24}
			deltaBytes := make([]byte, 3)
			deltaBytes[0] = byte(deltaInt64 >> 16)
			deltaBytes[1] = byte(deltaInt64 >> 8)
			deltaBytes[2] = byte(deltaInt64)
			return append(result, deltaBytes...)
		} else if deltaInt64 >= -2147483648 && deltaInt64 <= 2147483647 {
			result := []byte{baseFeeDelta32}
			deltaBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(deltaBytes, uint32(deltaInt64))
			return append(result, deltaBytes...)
		} else {
			result := []byte{baseFeeDelta64}
			deltaBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(deltaBytes, uint64(deltaInt64))
			return append(result, deltaBytes...)
		}
	}

	// Fallback to full encoding
	result := []byte{baseFeeEscape}
	baseFeeBytes := make([]byte, 32)
	b.baseFee.FillBytes(baseFeeBytes)
	return append(result, baseFeeBytes...)
}

// decodeWithDelta populates the fields of a DABlock from a byte slice using delta encoding.
func (b *daBlockV8) decodeWithDelta(data []byte, previousBlock *daBlockV8) (int, error) {
	offset := 0

	// Decode timestamp
	timestampBytesRead, err := b.decodeTimestamp(data[offset:], previousBlock)
	if err != nil {
		return 0, fmt.Errorf("failed to decode timestamp: %w", err)
	}
	offset += timestampBytesRead

	// Decode baseFee
	baseFeeBytesRead, err := b.decodeBaseFee(data[offset:], previousBlock)
	if err != nil {
		return 0, fmt.Errorf("failed to decode baseFee: %w", err)
	}
	offset += baseFeeBytesRead

	// Decode gasLimit
	gasLimitBytesRead, err := b.decodeGasLimit(data[offset:], previousBlock)
	if err != nil {
		return 0, fmt.Errorf("failed to decode gasLimit: %w", err)
	}
	offset += gasLimitBytesRead

	// Decode numTransactions
	numTxBytesRead, err := b.decodeNumTransactions(data[offset:])
	if err != nil {
		return 0, fmt.Errorf("failed to decode numTransactions: %w", err)
	}
	offset += numTxBytesRead

	// Decode numL1Messages
	numL1MsgBytesRead, err := b.decodeNumL1Messages(data[offset:])
	if err != nil {
		return 0, fmt.Errorf("failed to decode numL1Messages: %w", err)
	}
	offset += numL1MsgBytesRead

	return offset, nil
}

func (b *daBlockV8) decodeTimestamp(data []byte, previousBlock *daBlockV8) (int, error) {
	if len(data) < 1 {
		return 0, errors.New("insufficient data for timestamp")
	}

	if data[0] == deltaEscapeValue {
		if len(data) < 9 {
			return 0, errors.New("insufficient data for timestamp escape sequence")
		}
		b.timestamp = binary.BigEndian.Uint64(data[1:9])
		return 9, nil
	}

	if previousBlock == nil {
		return 0, errors.New("first block must use escape sequence for timestamp")
	}
	timestampDelta := data[0]
	b.timestamp = previousBlock.timestamp + uint64(timestampDelta)
	return 1, nil
}

func (b *daBlockV8) decodeBaseFee(data []byte, previousBlock *daBlockV8) (int, error) {
	if len(data) < 1 {
		return 0, errors.New("insufficient data for baseFee")
	}

	baseFeeType := data[0]

	switch baseFeeType {
	case baseFeeNoValue:
		b.baseFee = nil
		return 1, nil
	case baseFeeDelta8:
		if len(data) < 2 {
			return 0, errors.New("insufficient data for baseFee delta8")
		}
		if previousBlock == nil || previousBlock.baseFee == nil {
			return 0, errors.New("cannot apply delta to nil baseFee")
		}
		delta := int8(data[1])
		b.baseFee = new(big.Int).Add(previousBlock.baseFee, big.NewInt(int64(delta)))
		return 2, nil
	case baseFeeDelta16:
		if len(data) < 3 {
			return 0, errors.New("insufficient data for baseFee delta16")
		}
		if previousBlock == nil || previousBlock.baseFee == nil {
			return 0, errors.New("cannot apply delta to nil baseFee")
		}
		delta := int16(binary.BigEndian.Uint16(data[1:3]))
		b.baseFee = new(big.Int).Add(previousBlock.baseFee, big.NewInt(int64(delta)))
		return 3, nil
	case baseFeeDelta24:
		if len(data) < 4 {
			return 0, errors.New("insufficient data for baseFee delta24")
		}
		if previousBlock == nil || previousBlock.baseFee == nil {
			return 0, errors.New("cannot apply delta to nil baseFee")
		}
		delta := int32(data[1])<<16 | int32(binary.BigEndian.Uint16(data[2:4]))
		delta = (delta << 8) >> 8 // Sign extension
		b.baseFee = new(big.Int).Add(previousBlock.baseFee, big.NewInt(int64(delta)))
		return 4, nil
	case baseFeeDelta32:
		if len(data) < 5 {
			return 0, errors.New("insufficient data for baseFee delta32")
		}
		if previousBlock == nil || previousBlock.baseFee == nil {
			return 0, errors.New("cannot apply delta to nil baseFee")
		}
		delta := int32(binary.BigEndian.Uint32(data[1:5]))
		b.baseFee = new(big.Int).Add(previousBlock.baseFee, big.NewInt(int64(delta)))
		return 5, nil
	case baseFeeDelta64:
		if len(data) < 9 {
			return 0, errors.New("insufficient data for baseFee delta64")
		}
		if previousBlock == nil || previousBlock.baseFee == nil {
			return 0, errors.New("cannot apply delta to nil baseFee")
		}
		delta := int64(binary.BigEndian.Uint64(data[1:9]))
		b.baseFee = new(big.Int).Add(previousBlock.baseFee, big.NewInt(delta))
		return 9, nil
	case baseFeeEscape:
		if len(data) < 33 {
			return 0, errors.New("insufficient data for baseFee escape sequence")
		}
		b.baseFee = new(big.Int).SetBytes(data[1:33])
		return 33, nil
	default:
		return 0, fmt.Errorf("invalid baseFee encoding type: %d", baseFeeType)
	}
}

func (b *daBlockV8) decodeGasLimit(data []byte, previousBlock *daBlockV8) (int, error) {
	if len(data) < 1 {
		return 0, errors.New("insufficient data for gasLimit")
	}

	if data[0] == deltaEscapeValue {
		if len(data) < 9 {
			return 0, errors.New("insufficient data for gasLimit escape sequence")
		}
		b.gasLimit = binary.BigEndian.Uint64(data[1:9])
		return 9, nil
	}

	if previousBlock == nil {
		return 0, errors.New("first block must use escape sequence for gasLimit")
	}
	gasLimitDelta := int8(data[0])
	b.gasLimit = uint64(int64(previousBlock.gasLimit) + int64(gasLimitDelta))
	return 1, nil
}

func (b *daBlockV8) decodeNumTransactions(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, errors.New("insufficient data for numTransactions")
	}

	if data[0] == deltaEscapeValue {
		if len(data) < 3 {
			return 0, errors.New("insufficient data for numTransactions escape sequence")
		}
		b.numTransactions = binary.BigEndian.Uint16(data[1:3])
		return 3, nil
	}

	b.numTransactions = uint16(data[0])
	return 1, nil
}

func (b *daBlockV8) decodeNumL1Messages(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, errors.New("insufficient data for numL1Messages")
	}

	if data[0] == deltaEscapeValue {
		if len(data) < 3 {
			return 0, errors.New("insufficient data for numL1Messages escape sequence")
		}
		b.numL1Messages = binary.BigEndian.Uint16(data[1:3])
		return 3, nil
	}

	b.numL1Messages = uint16(data[0])
	return 1, nil
}

// iterateAndVerifyBlocksAndL1MessagesV8 iterates over the blocks and verifies the blocks and L1 messages.
func iterateAndVerifyBlocksAndL1MessagesV8(prevL1MessageQueueHash, postL1MessageQueueHash common.Hash, blocks []*Block, totalL1MessagePoppedBefore *uint64, initialL2BlockNumberCallback func(initialL2BlockNumber uint64), blockCallBack func(block *Block, daBlock *daBlockV8) error) error {
	if len(blocks) == 0 {
		return errors.New("no blocks to iterate")
	}

	if !blocks[0].Header.Number.IsUint64() {
		return errors.New("block number of initial block is not uint64")
	}
	initialL2BlockNumber := blocks[0].Header.Number.Uint64()
	var startL1MessageIndex *uint64
	if totalL1MessagePoppedBefore != nil {
		startL1MessageIndex = new(uint64)
		*startL1MessageIndex = *totalL1MessagePoppedBefore
	}

	initialL2BlockNumberCallback(initialL2BlockNumber)

	for i, block := range blocks {
		if !block.Header.Number.IsUint64() {
			return fmt.Errorf("block number is not a uint64: %s", block.Header.Number.String())
		}
		if block.Header.Number.Uint64() != initialL2BlockNumber+uint64(i) {
			return fmt.Errorf("invalid block number: expected %d but got %d", initialL2BlockNumber+uint64(i), block.Header.Number.Uint64())
		}

		daBlock, err := newDABlockV8FromBlockWithValidation(block, startL1MessageIndex)
		if err != nil {
			return fmt.Errorf("failed to create DABlock from block %d: %w", block.Header.Number.Uint64(), err)
		}
		if daBlock.NumL1Messages() > 0 {
			if startL1MessageIndex == nil {
				startL1MessageIndex = new(uint64)
				*startL1MessageIndex = daBlock.lowestL1MessageQueueIndex
			}
			*startL1MessageIndex += uint64(daBlock.NumL1Messages())
		}

		if err = blockCallBack(block, daBlock); err != nil {
			return fmt.Errorf("failed to process block %d: %w", block.Header.Number.Uint64(), err)
		}
	}

	computedPostL1MessageQueueHash, err := MessageQueueV2ApplyL1MessagesFromBlocks(prevL1MessageQueueHash, blocks)
	if err != nil {
		return fmt.Errorf("failed to apply L1 messages to prevL1MessageQueueHash: %w", err)
	}
	if computedPostL1MessageQueueHash != postL1MessageQueueHash {
		return fmt.Errorf("failed to sanity check postL1MessageQueueHash after applying all L1 messages: expected %s, got %s", computedPostL1MessageQueueHash, postL1MessageQueueHash)
	}

	return nil
}
