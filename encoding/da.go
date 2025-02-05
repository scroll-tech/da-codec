package encoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/klauspost/compress/zstd"
	"github.com/scroll-tech/go-ethereum/crypto"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/params"
)

// blsModulus is the BLS modulus defined in EIP-4844.
var blsModulus = new(big.Int).SetBytes(common.FromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"))

// blockContextByteSize is the size of the block context in bytes.
const blockContextByteSize = 60

// blockContextBytesForHashing is the size of the block context in bytes for hashing.
const blockContextBytesForHashing = blockContextByteSize - 2

// txLenByteSize is the size of the transaction length in bytes.
const txLenByteSize = 4

// maxBlobBytes is the maximum number of bytes that can be stored in a blob.
const maxBlobBytes = 131072

// maxEffectiveBlobBytes is the maximum number of bytes that can be stored in a blob.
// We can only utilize 31/32 of a blob.
const maxEffectiveBlobBytes = maxBlobBytes / 32 * 31

// minCompressedDataCheckSize is the minimum size of compressed data to check compatibility.
// only used in codecv2 and codecv3.
const minCompressedDataCheckSize = 131072

// kzgPointByteSize is the size of a KZG point (z and y) in bytes.
const kzgPointByteSize = 32

// zstdMagicNumber is the magic number for zstd compressed data header.
var zstdMagicNumber = []byte{0x28, 0xb5, 0x2f, 0xfd}

const (
	daBatchOffsetVersion    = 0
	daBatchOffsetBatchIndex = 1
	daBatchOffsetDataHash   = 25
)

const (
	daBatchV0OffsetL1MessagePopped        = 9
	daBatchV0OffsetTotalL1MessagePopped   = 17
	daBatchV0OffsetParentBatchHash        = 57
	daBatchV0OffsetSkippedL1MessageBitmap = 89
	daBatchV0EncodedMinLength             = 89 // min length of a v0 da batch, when there are no skipped L1 messages
)

const (
	daBatchV1OffsetL1MessagePopped        = 9
	daBatchV1OffsetTotalL1MessagePopped   = 17
	daBatchV1OffsetBlobVersionedHash      = 57
	daBatchV1OffsetParentBatchHash        = 89
	daBatchV1OffsetSkippedL1MessageBitmap = 121
	daBatchV1EncodedMinLength             = 121 // min length of a v1 da batch, when there are no skipped L1 messages
)

const (
	daBatchV3OffsetL1MessagePopped      = 9
	daBatchV3OffsetTotalL1MessagePopped = 17
	daBatchV3OffsetBlobVersionedHash    = 57
	daBatchV3OffsetParentBatchHash      = 89
	daBatchV3OffsetLastBlockTimestamp   = 121
	daBatchV3OffsetBlobDataProof        = 129
	daBatchV3EncodedLength              = 193
)

const (
	payloadLengthBytes                 = 4
	calldataNonZeroByteGas             = 16
	coldSloadGas                       = 2100
	coldAddressAccessGas               = 2600
	warmAddressAccessGas               = 100
	warmSloadGas                       = 100
	baseTxGas                          = 21000
	sstoreGas                          = 20000
	extraGasCost                       = 100000 // over-estimate the gas cost for ops like _getAdmin, _implementation, _requireNotPaused, etc
	blobTxPointEvaluationPrecompileGas = 50000
	skippedL1MessageBitmapByteSize     = 32
	functionSignatureBytes             = 4
	defaultParameterBytes              = 32
)

// Block represents an L2 block.
type Block struct {
	Header         *types.Header
	Transactions   []*types.TransactionData
	WithdrawRoot   common.Hash           `json:"withdraw_trie_root,omitempty"`
	RowConsumption *types.RowConsumption `json:"row_consumption,omitempty"`
}

// Chunk represents a group of blocks.
type Chunk struct {
	Blocks []*Block `json:"blocks"`

	// CodecV7. Used for chunk creation in relayer.
	InitialL1MessageQueueHash common.Hash
	LastL1MessageQueueHash    common.Hash
}

// Batch represents a batch of chunks.
type Batch struct {
	Index                      uint64
	TotalL1MessagePoppedBefore uint64
	ParentBatchHash            common.Hash
	Chunks                     []*Chunk

	// CodecV7
	InitialL1MessageIndex     uint64
	InitialL1MessageQueueHash common.Hash
	LastL1MessageQueueHash    common.Hash
	Blocks                    []*Block
}

// NumL1Messages returns the number of L1 messages in this block.
// This number is the sum of included and skipped L1 messages.
func (b *Block) NumL1Messages(totalL1MessagePoppedBefore uint64) uint64 {
	var lastQueueIndex *uint64
	for _, txData := range b.Transactions {
		if txData.Type == types.L1MessageTxType {
			lastQueueIndex = &txData.Nonce
		}
	}
	if lastQueueIndex == nil {
		return 0
	}
	// note: last queue index included before this block is totalL1MessagePoppedBefore - 1
	// TODO: cache results
	return *lastQueueIndex - totalL1MessagePoppedBefore + 1
}

// NumL1MessagesNoSkipping returns the number of L1 messages and the highest queue index in this block.
// This method assumes that L1 messages can't be skipped.
func (b *Block) NumL1MessagesNoSkipping() (uint16, uint64, error) {
	var count uint16
	var prevQueueIndex *uint64

	for _, txData := range b.Transactions {
		if txData.Type != types.L1MessageTxType {
			continue
		}

		// If prevQueueIndex is nil, it means this is the first L1 message in the block.
		if prevQueueIndex == nil {
			prevQueueIndex = &txData.Nonce
			count++
			continue
		}

		// Check if the queue index is consecutive.
		if txData.Nonce != *prevQueueIndex+1 {
			return 0, 0, fmt.Errorf("unexpected queue index: expected %d, got %d", *prevQueueIndex+1, txData.Nonce)
		}

		if count == math.MaxUint16 {
			return 0, 0, errors.New("number of L1 messages exceeds max uint16")
		}
		count++
		prevQueueIndex = &txData.Nonce
	}

	if prevQueueIndex == nil {
		return 0, 0, nil
	}
	return count, *prevQueueIndex, nil
}

// NumL2Transactions returns the number of L2 transactions in this block.
func (b *Block) NumL2Transactions() uint64 {
	var count uint64
	for _, txData := range b.Transactions {
		if txData.Type != types.L1MessageTxType {
			count++
		}
	}
	return count
}

// NumL1Messages returns the number of L1 messages in this chunk.
// This number is the sum of included and skipped L1 messages.
func (c *Chunk) NumL1Messages(totalL1MessagePoppedBefore uint64) uint64 {
	var numL1Messages uint64
	for _, block := range c.Blocks {
		numL1MessagesInBlock := block.NumL1Messages(totalL1MessagePoppedBefore)
		numL1Messages += numL1MessagesInBlock
		totalL1MessagePoppedBefore += numL1MessagesInBlock
	}
	// TODO: cache results
	return numL1Messages
}

// convertTxDataToRLPEncoding transforms []*TransactionData into []*types.Transaction.
func convertTxDataToRLPEncoding(txData *types.TransactionData) ([]byte, error) {
	data, err := hexutil.Decode(txData.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode txData.Data: data=%v, err=%w", txData.Data, err)
	}

	var tx *types.Transaction
	switch txData.Type {
	case types.LegacyTxType:
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    txData.Nonce,
			To:       txData.To,
			Value:    txData.Value.ToInt(),
			Gas:      txData.Gas,
			GasPrice: txData.GasPrice.ToInt(),
			Data:     data,
			V:        txData.V.ToInt(),
			R:        txData.R.ToInt(),
			S:        txData.S.ToInt(),
		})

	case types.AccessListTxType:
		tx = types.NewTx(&types.AccessListTx{
			ChainID:    txData.ChainId.ToInt(),
			Nonce:      txData.Nonce,
			To:         txData.To,
			Value:      txData.Value.ToInt(),
			Gas:        txData.Gas,
			GasPrice:   txData.GasPrice.ToInt(),
			Data:       data,
			AccessList: txData.AccessList,
			V:          txData.V.ToInt(),
			R:          txData.R.ToInt(),
			S:          txData.S.ToInt(),
		})

	case types.DynamicFeeTxType:
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:    txData.ChainId.ToInt(),
			Nonce:      txData.Nonce,
			To:         txData.To,
			Value:      txData.Value.ToInt(),
			Gas:        txData.Gas,
			GasTipCap:  txData.GasTipCap.ToInt(),
			GasFeeCap:  txData.GasFeeCap.ToInt(),
			Data:       data,
			AccessList: txData.AccessList,
			V:          txData.V.ToInt(),
			R:          txData.R.ToInt(),
			S:          txData.S.ToInt(),
		})

	case types.L1MessageTxType: // L1MessageTxType is not supported
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported tx type: %d", txData.Type)
	}

	rlpTxData, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal binary of the tx: tx=%v, err=%w", tx, err)
	}

	return rlpTxData, nil
}

// CrcMax calculates the maximum row consumption of crc.
func (c *Chunk) CrcMax() (uint64, error) {
	// Map sub-circuit name to row count
	crc := make(map[string]uint64)

	// if no blocks have row consumption, this is an euclid chunk
	isEuclidChunk := slices.IndexFunc(c.Blocks, func(block *Block) bool {
		return block.RowConsumption != nil
	}) == -1

	if isEuclidChunk {
		return 0, nil
	}

	// Iterate over blocks, accumulate row consumption
	for _, block := range c.Blocks {
		if block.RowConsumption == nil {
			return 0, fmt.Errorf("block (%d, %v) has nil RowConsumption", block.Header.Number, block.Header.Hash().Hex())
		}
		for _, subCircuit := range *block.RowConsumption {
			crc[subCircuit.Name] += subCircuit.RowNumber
		}
	}

	// Find the maximum row consumption
	var maxVal uint64
	for _, value := range crc {
		if value > maxVal {
			maxVal = value
		}
	}

	// Return the maximum row consumption
	return maxVal, nil
}

// NumTransactions calculates the total number of transactions in a Chunk.
func (c *Chunk) NumTransactions() uint64 {
	var totalTxNum uint64
	for _, block := range c.Blocks {
		totalTxNum += uint64(len(block.Transactions))
	}
	return totalTxNum
}

// NumL2Transactions calculates the total number of L2 transactions in a Chunk.
func (c *Chunk) NumL2Transactions() uint64 {
	var totalTxNum uint64
	for _, block := range c.Blocks {
		totalTxNum += block.NumL2Transactions()
	}
	return totalTxNum
}

// TotalGasUsed calculates the total gas of transactions in a Chunk.
func (c *Chunk) TotalGasUsed() uint64 {
	var totalGasUsed uint64
	for _, block := range c.Blocks {
		totalGasUsed += block.Header.GasUsed
	}
	return totalGasUsed
}

// StateRoot gets the state root after committing/finalizing the batch.
func (b *Batch) StateRoot() common.Hash {
	numChunks := len(b.Chunks)
	if len(b.Chunks) == 0 {
		return common.Hash{}
	}
	lastChunkBlockNum := len(b.Chunks[numChunks-1].Blocks)
	return b.Chunks[len(b.Chunks)-1].Blocks[lastChunkBlockNum-1].Header.Root
}

// WithdrawRoot gets the withdraw root after committing/finalizing the batch.
func (b *Batch) WithdrawRoot() common.Hash {
	numChunks := len(b.Chunks)
	if len(b.Chunks) == 0 {
		return common.Hash{}
	}
	lastChunkBlockNum := len(b.Chunks[numChunks-1].Blocks)
	return b.Chunks[len(b.Chunks)-1].Blocks[lastChunkBlockNum-1].WithdrawRoot
}

// TxsToTxsData converts transactions to a TransactionData array.
func TxsToTxsData(txs types.Transactions) []*types.TransactionData {
	txsData := make([]*types.TransactionData, len(txs))
	for i, tx := range txs {
		v, r, s := tx.RawSignatureValues()

		nonce := tx.Nonce()

		// We need QueueIndex in `NewBatchHeader`. However, `TransactionData`
		// does not have this field. Since `L1MessageTx` do not have a nonce,
		// we reuse this field for storing the queue index.
		if msg := tx.AsL1MessageTx(); msg != nil {
			nonce = msg.QueueIndex
		}

		txsData[i] = &types.TransactionData{
			Type:       tx.Type(),
			TxHash:     tx.Hash().String(),
			Nonce:      nonce,
			ChainId:    (*hexutil.Big)(tx.ChainId()),
			Gas:        tx.Gas(),
			GasPrice:   (*hexutil.Big)(tx.GasPrice()),
			GasTipCap:  (*hexutil.Big)(tx.GasTipCap()),
			GasFeeCap:  (*hexutil.Big)(tx.GasFeeCap()),
			To:         tx.To(),
			Value:      (*hexutil.Big)(tx.Value()),
			Data:       hexutil.Encode(tx.Data()),
			IsCreate:   tx.To() == nil,
			AccessList: tx.AccessList(),
			V:          (*hexutil.Big)(v),
			R:          (*hexutil.Big)(r),
			S:          (*hexutil.Big)(s),
		}
	}
	return txsData
}

// Fast testing if the compressed data is compatible with our circuit
// (require specified frame header and each block is compressed)
func checkCompressedDataCompatibility(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("too small size (0x%x), what is it?", data)
	}

	fheader := data[0]
	// it is not the encoding type we expected in our zstd header
	if fheader&63 != 32 {
		return fmt.Errorf("unexpected header type (%x)", fheader)
	}

	// skip content size
	switch fheader >> 6 {
	case 0:
		data = data[2:]
	case 1:
		data = data[3:]
	case 2:
		data = data[5:]
	case 3:
		data = data[9:]
	default:
		panic("impossible")
	}

	isLast := false
	// scan each block until done
	for len(data) > 3 && !isLast {
		isLast = (data[0] & 1) == 1
		blkType := (data[0] >> 1) & 3
		blkSize := (uint(data[2])*65536 + uint(data[1])*256 + uint(data[0])) >> 3
		if blkType != 2 {
			return fmt.Errorf("unexpected blk type {%d}, size {%d}, last {%t}", blkType, blkSize, isLast)
		}
		if len(data) < 3+int(blkSize) {
			return fmt.Errorf("wrong data len {%d}, expect min {%d}", len(data), 3+blkSize)
		}
		data = data[3+blkSize:]
	}

	// Should we return invalid if isLast is still false?
	if !isLast {
		return fmt.Errorf("unexpected end before last block")
	}

	return nil
}

// makeBlobCanonical converts the raw blob data into the canonical blob representation of 4096 BLSFieldElements.
func makeBlobCanonical(blobBytes []byte) (*kzg4844.Blob, error) {
	if len(blobBytes) > maxEffectiveBlobBytes {
		return nil, fmt.Errorf("oversized batch payload, blob bytes length: %v, max length: %v", len(blobBytes), maxEffectiveBlobBytes)
	}

	// the canonical (padded) blob payload
	var blob kzg4844.Blob

	// encode blob payload by prepending every 31 bytes with 1 zero byte
	index := 0

	for from := 0; from < len(blobBytes); from += 31 {
		to := from + 31
		if to > len(blobBytes) {
			to = len(blobBytes)
		}
		copy(blob[index+1:], blobBytes[from:to])
		index += 32
	}

	return &blob, nil
}

// bytesFromBlobCanonical converts the canonical blob representation into the raw blob data
func bytesFromBlobCanonical(blob *kzg4844.Blob) [maxEffectiveBlobBytes]byte {
	var blobBytes [maxEffectiveBlobBytes]byte
	for from := 0; from < len(blob); from += 32 {
		copy(blobBytes[from/32*31:], blob[from+1:from+32])
	}
	return blobBytes
}

// decompressScrollBlobToBatch decompresses the given blob bytes into scroll batch bytes
func decompressScrollBlobToBatch(compressedBytes []byte) ([]byte, error) {
	// decompress data in stream and in batches of bytes, because we don't know actual length of compressed data
	var res []byte
	readBatchSize := maxBlobBytes
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
		// the error here is supposed to be EOF or similar that indicates that buffer has been read until the end
		// we should return all data that read by this moment
		if i < readBatchSize || err != nil {
			break
		}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("failed to decompress blob bytes")
	}
	return res, nil
}

// calculatePaddedBlobSize calculates the required size on blob storage
// where every 32 bytes can store only 31 bytes of actual data, with the first byte being zero.
func calculatePaddedBlobSize(dataSize uint64) uint64 {
	paddedSize := (dataSize / 31) * 32

	if dataSize%31 != 0 {
		paddedSize += 1 + dataSize%31 // Add 1 byte for the first empty byte plus the remainder bytes
	}

	return paddedSize
}

// constructBatchPayloadInBlob constructs the batch payload.
// This function is only used in compressed batch payload length estimation.
func constructBatchPayloadInBlob(chunks []*Chunk, codec Codec) ([]byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + codec.MaxNumChunksPerBatch()*4

	// batchBytes represents the raw (un-compressed and un-padded) blob payload
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
				rlpTxData, err := convertTxDataToRLPEncoding(tx)
				if err != nil {
					return nil, err
				}
				batchBytes = append(batchBytes, rlpTxData...)
			}
		}

		// batch metadata: chunki_size
		chunkSize := len(batchBytes) - currentChunkStartIndex
		binary.BigEndian.PutUint32(batchBytes[2+4*chunkID:], uint32(chunkSize))
	}
	return batchBytes, nil
}

// getKeccak256Gas calculates the gas cost for computing the keccak256 hash of a given size.
func getKeccak256Gas(size uint64) uint64 {
	return getMemoryExpansionCost(size) + 30 + 6*((size+31)/32)
}

// getMemoryExpansionCost calculates the cost of memory expansion for a given memoryByteSize.
func getMemoryExpansionCost(memoryByteSize uint64) uint64 {
	memorySizeWord := (memoryByteSize + 31) / 32
	memoryCost := (memorySizeWord*memorySizeWord)/512 + (3 * memorySizeWord)
	return memoryCost
}

// getTxPayloadLength calculates the length of the transaction payload.
func getTxPayloadLength(txData *types.TransactionData) (uint64, error) {
	rlpTxData, err := convertTxDataToRLPEncoding(txData)
	if err != nil {
		return 0, err
	}
	return uint64(len(rlpTxData)), nil
}

// blobDataProofFromValues creates the blob data proof from the given values.
// Memory layout of ``_blobDataProof``:
// | z       | y       | kzg_commitment | kzg_proof |
// |---------|---------|----------------|-----------|
// | bytes32 | bytes32 | bytes48        | bytes48   |

func blobDataProofFromValues(z kzg4844.Point, y kzg4844.Claim, commitment kzg4844.Commitment, proof kzg4844.Proof) []byte {
	result := make([]byte, 32+32+48+48)

	copy(result[0:32], z[:])
	copy(result[32:64], y[:])
	copy(result[64:112], commitment[:])
	copy(result[112:160], proof[:])

	return result
}

var errSmallLength error = fmt.Errorf("length of blob bytes is too small")

// getNextTx parses blob bytes to find length of payload of next Tx and decode it
func getNextTx(bytes []byte, index int) (*types.Transaction, int, error) {
	var nextIndex int
	length := len(bytes)
	if length < index+1 {
		return nil, 0, errSmallLength
	}
	var txBytes []byte
	if bytes[index] <= 0x7f {
		// the first byte is transaction type, rlp encoding begins from next byte
		txBytes = append(txBytes, bytes[index])
		index++
	}
	if length < index+1 {
		return nil, 0, errSmallLength
	}
	if bytes[index] >= 0xc0 && bytes[index] <= 0xf7 {
		// length of payload is simply bytes[index] - 0xc0
		payloadLen := int(bytes[index] - 0xc0)
		if length < index+1+payloadLen {
			return nil, 0, errSmallLength
		}
		txBytes = append(txBytes, bytes[index:index+1+payloadLen]...)
		nextIndex = index + 1 + payloadLen
	} else if bytes[index] > 0xf7 {
		// the length of payload is encoded in next bytes[index] - 0xf7 bytes
		// length of bytes representation of length of payload
		lenPayloadLen := int(bytes[index] - 0xf7)
		if length < index+1+lenPayloadLen {
			return nil, 0, errSmallLength
		}
		lenBytes := bytes[index+1 : index+1+lenPayloadLen]
		for len(lenBytes) < 8 {
			lenBytes = append([]byte{0x0}, lenBytes...)
		}
		payloadLen := binary.BigEndian.Uint64(lenBytes)

		if length < index+1+lenPayloadLen+int(payloadLen) {
			return nil, 0, errSmallLength
		}
		txBytes = append(txBytes, bytes[index:index+1+lenPayloadLen+int(payloadLen)]...)
		nextIndex = index + 1 + lenPayloadLen + int(payloadLen)
	} else {
		return nil, 0, fmt.Errorf("incorrect format of rlp encoding")
	}
	tx := &types.Transaction{}
	err := tx.UnmarshalBinary(txBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to unmarshal tx, err: %w", err)
	}
	return tx, nextIndex, nil
}

// decodeTxsFromBytes decodes txs from blob bytes and writes to chunks
func decodeTxsFromBytes(blobBytes []byte, chunks []*DAChunkRawTx, maxNumChunks int) error {
	numChunks := int(binary.BigEndian.Uint16(blobBytes[0:2]))
	if numChunks != len(chunks) {
		return fmt.Errorf("blob chunk number is not same as calldata, blob num chunks: %d, calldata num chunks: %d", numChunks, len(chunks))
	}
	index := 2 + maxNumChunks*4
	for chunkID, chunk := range chunks {
		var transactions []types.Transactions
		chunkSize := int(binary.BigEndian.Uint32(blobBytes[2+4*chunkID : 2+4*chunkID+4]))

		chunkBytes := blobBytes[index : index+chunkSize]
		curIndex := 0
		for _, block := range chunk.Blocks {
			var blockTransactions types.Transactions
			txNum := int(block.NumTransactions()) - int(block.NumL1Messages())
			if txNum < 0 {
				return fmt.Errorf("invalid transaction count: NumL1Messages (%d) exceeds NumTransactions (%d)", block.NumL1Messages(), block.NumTransactions())
			}
			for i := 0; i < txNum; i++ {
				tx, nextIndex, err := getNextTx(chunkBytes, curIndex)
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

// GetHardforkName returns the name of the hardfork active at the given block height and timestamp.
func GetHardforkName(config *params.ChainConfig, blockHeight, blockTimestamp uint64) string {
	blockHeightBigInt := new(big.Int).SetUint64(blockHeight)
	if !config.IsBernoulli(blockHeightBigInt) {
		return "homestead"
	} else if !config.IsCurie(blockHeightBigInt) {
		return "bernoulli"
	} else if !config.IsDarwin(blockTimestamp) {
		return "curie"
	} else if !config.IsDarwinV2(blockTimestamp) {
		return "darwin"
	} else if !config.IsEuclid(blockTimestamp) {
		return "darwinV2"
	} else if !config.IsEuclidV2(blockTimestamp) {
		return "euclid"
	} else {
		return "euclidV2"
	}
}

// GetCodecVersion returns the encoding codec version for the given block height and timestamp.
func GetCodecVersion(config *params.ChainConfig, blockHeight, blockTimestamp uint64) CodecVersion {
	blockHeightBigInt := new(big.Int).SetUint64(blockHeight)
	if !config.IsBernoulli(blockHeightBigInt) {
		return CodecV0
	} else if !config.IsCurie(blockHeightBigInt) {
		return CodecV1
	} else if !config.IsDarwin(blockTimestamp) {
		return CodecV2
	} else if !config.IsDarwinV2(blockTimestamp) {
		return CodecV3
	} else if !config.IsEuclid(blockTimestamp) {
		return CodecV4
	} else if !config.IsEuclidV2(blockTimestamp) {
		// V5 is skipped, because it is only used for the special Euclid transition batch that we handle explicitly
		return CodecV6
	} else {
		return CodecV7
	}
}

// CheckChunkCompressedDataCompatibility checks compressed data compatibility of a batch built by a single chunk.
func CheckChunkCompressedDataCompatibility(chunk *Chunk, codecVersion CodecVersion) (bool, error) {
	codec, err := CodecFromVersion(codecVersion)
	if err != nil {
		return false, fmt.Errorf("failed to get codec from version: %w", err)
	}
	return codec.CheckChunkCompressedDataCompatibility(chunk)
}

// CheckBatchCompressedDataCompatibility checks compressed data compatibility of a batch built by a single chunk.
func CheckBatchCompressedDataCompatibility(batch *Batch, codecVersion CodecVersion) (bool, error) {
	codec, err := CodecFromVersion(codecVersion)
	if err != nil {
		return false, fmt.Errorf("failed to get codec from version: %w", err)
	}
	return codec.CheckBatchCompressedDataCompatibility(batch)
}

// GetChunkEnableCompression returns whether to enable compression for the given block height and timestamp.
func GetChunkEnableCompression(codecVersion CodecVersion, chunk *Chunk) (bool, error) {
	switch codecVersion {
	case CodecV0, CodecV1:
		return false, nil
	case CodecV2, CodecV3:
		return true, nil
	case CodecV4, CodecV5, CodecV6, CodecV7:
		return CheckChunkCompressedDataCompatibility(chunk, codecVersion)
	default:
		return false, fmt.Errorf("unsupported codec version: %v", codecVersion)
	}
}

// GetBatchEnableCompression returns whether to enable compression for the given block height and timestamp.
func GetBatchEnableCompression(codecVersion CodecVersion, batch *Batch) (bool, error) {
	switch codecVersion {
	case CodecV0, CodecV1:
		return false, nil
	case CodecV2, CodecV3:
		return true, nil
	case CodecV4, CodecV5, CodecV6, CodecV7:
		return CheckBatchCompressedDataCompatibility(batch, codecVersion)
	default:
		return false, fmt.Errorf("unsupported codec version: %v", codecVersion)
	}
}

func MessageQueueV2ApplyL1MessagesFromBlocks(initialQueueHash common.Hash, blocks []*Block) (common.Hash, error) {
	rollingHash := initialQueueHash
	for _, block := range blocks {
		for _, txData := range block.Transactions {
			if txData.Type != types.L1MessageTxType {
				continue
			}

			data, err := hexutil.Decode(txData.Data)
			if err != nil {
				return common.Hash{}, fmt.Errorf("failed to decode txData.Data: data=%v, err=%w", txData.Data, err)
			}

			l1Message := &types.L1MessageTx{
				QueueIndex: txData.Nonce,
				Gas:        txData.Gas,
				To:         txData.To,
				Value:      txData.Value.ToInt(),
				Data:       data,
				Sender:     txData.From,
			}

			rollingHash = messageQueueV2ApplyL1Message(rollingHash, l1Message)
		}
	}

	return rollingHash, nil
}

func MessageQueueV2ApplyL1Messages(initialQueueHash common.Hash, messages []*types.L1MessageTx) common.Hash {
	rollingHash := initialQueueHash
	for _, message := range messages {
		rollingHash = messageQueueV2ApplyL1Message(rollingHash, message)
	}

	return rollingHash
}

func messageQueueV2ApplyL1Message(initialQueueHash common.Hash, message *types.L1MessageTx) common.Hash {
	rollingHash := crypto.Keccak256Hash(initialQueueHash.Bytes(), types.NewTx(message).Hash().Bytes())

	return messageQueueV2EncodeRollingHash(rollingHash)
}

func messageQueueV2EncodeRollingHash(rollingHash common.Hash) common.Hash {
	// clear last 36 bits

	// Clear the lower 4 bits of byte 26 (preserving the upper 4 bits)
	rollingHash[27] &= 0xF0

	// Clear the next 4 bytes (32 bits total)
	rollingHash[28] = 0
	rollingHash[29] = 0
	rollingHash[30] = 0
	rollingHash[31] = 0

	return rollingHash
}
