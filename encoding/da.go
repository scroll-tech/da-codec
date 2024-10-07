package encoding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/klauspost/compress/zstd"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/scroll-tech/go-ethereum/params"
)

// BLSModulus is the BLS modulus defined in EIP-4844.
var BLSModulus = new(big.Int).SetBytes(common.FromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"))

// CalldataNonZeroByteGas is the gas consumption per non zero byte in calldata.
const CalldataNonZeroByteGas = 16

// BlockContextByteSize is the size of the block context in bytes.
const BlockContextByteSize = 60

// TxLenByteSize is the size of the transaction length in bytes.
const TxLenByteSize = 4

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
}

// Batch represents a batch of chunks.
type Batch struct {
	Index                      uint64
	TotalL1MessagePoppedBefore uint64
	ParentBatchHash            common.Hash
	Chunks                     []*Chunk
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

// ConvertTxDataToRLPEncoding transforms []*TransactionData into []*types.Transaction.
func ConvertTxDataToRLPEncoding(txData *types.TransactionData, useMockTxData bool) ([]byte, error) {
	data, err := hexutil.Decode(txData.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode txData.Data: data=%v, err=%w", txData.Data, err)
	}

	// This mock param is only used in testing comparing batch challenges with standard test cases.
	// These tests use this param to set the tx data for convenience.
	if useMockTxData {
		return data, nil
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

// L2GasUsed calculates the total gas of L2 transactions in a Chunk.
func (c *Chunk) L2GasUsed() uint64 {
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
func CheckCompressedDataCompatibility(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("too small size (%x), what is it?", data)
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

// MakeBlobCanonical converts the raw blob data into the canonical blob representation of 4096 BLSFieldElements.
func MakeBlobCanonical(blobBytes []byte) (*kzg4844.Blob, error) {
	// blob contains 131072 bytes but we can only utilize 31/32 of these
	if len(blobBytes) > 126976 {
		return nil, fmt.Errorf("oversized batch payload, blob bytes length: %v, max length: %v", len(blobBytes), 126976)
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

// BytesFromBlobCanonical converts the canonical blob representation into the raw blob data
func BytesFromBlobCanonical(blob *kzg4844.Blob) [126976]byte {
	var blobBytes [126976]byte
	for from := 0; from < len(blob); from += 32 {
		copy(blobBytes[from/32*31:], blob[from+1:from+32])
	}
	return blobBytes
}

// DecompressScrollBlobToBatch decompresses the given blob bytes into scroll batch bytes
func DecompressScrollBlobToBatch(compressedBytes []byte) ([]byte, error) {
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

// CalculatePaddedBlobSize calculates the required size on blob storage
// where every 32 bytes can store only 31 bytes of actual data, with the first byte being zero.
func CalculatePaddedBlobSize(dataSize uint64) uint64 {
	paddedSize := (dataSize / 31) * 32

	if dataSize%31 != 0 {
		paddedSize += 1 + dataSize%31 // Add 1 byte for the first empty byte plus the remainder bytes
	}

	return paddedSize
}

// ConstructBatchPayloadInBlob constructs the batch payload.
// This function is only used in compressed batch payload length estimation.
func ConstructBatchPayloadInBlob(chunks []*Chunk, MaxNumChunks uint64) ([]byte, error) {
	// metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
	metadataLength := 2 + MaxNumChunks*4

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
				rlpTxData, err := ConvertTxDataToRLPEncoding(tx, false /* no mock */)
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

// GetKeccak256Gas calculates the gas cost for computing the keccak256 hash of a given size.
func GetKeccak256Gas(size uint64) uint64 {
	return GetMemoryExpansionCost(size) + 30 + 6*((size+31)/32)
}

// GetMemoryExpansionCost calculates the cost of memory expansion for a given memoryByteSize.
func GetMemoryExpansionCost(memoryByteSize uint64) uint64 {
	memorySizeWord := (memoryByteSize + 31) / 32
	memoryCost := (memorySizeWord*memorySizeWord)/512 + (3 * memorySizeWord)
	return memoryCost
}

// GetTxPayloadLength calculates the length of the transaction payload.
func GetTxPayloadLength(txData *types.TransactionData) (uint64, error) {
	rlpTxData, err := ConvertTxDataToRLPEncoding(txData, false /* no mock */)
	if err != nil {
		return 0, err
	}
	return uint64(len(rlpTxData)), nil
}

// BlobDataProofFromValues creates the blob data proof from the given values.
// Memory layout of ``_blobDataProof``:
// | z       | y       | kzg_commitment | kzg_proof |
// |---------|---------|----------------|-----------|
// | bytes32 | bytes32 | bytes48        | bytes48   |

func BlobDataProofFromValues(z kzg4844.Point, y kzg4844.Claim, commitment kzg4844.Commitment, proof kzg4844.Proof) []byte {
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

// DecodeTxsFromBytes decodes txs from blob bytes and writes to chunks
func DecodeTxsFromBytes(blobBytes []byte, chunks []*DAChunkRawTx, maxNumChunks int) error {
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
			txNum := int(block.NumTransactions() - block.NumL1Messages())
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
	if !config.IsBernoulli(new(big.Int).SetUint64(blockHeight)) {
		return "homestead"
	} else if !config.IsCurie(new(big.Int).SetUint64(blockHeight)) {
		return "bernoulli"
	} else if !config.IsDarwin(blockTimestamp) {
		return "curie"
	} else if !config.IsDarwinV2(blockTimestamp) {
		return "darwin"
	} else {
		return "darwinV2"
	}
}

// GetCodecVersion returns the encoding codec version for the given block height and timestamp.
func GetCodecVersion(config *params.ChainConfig, blockHeight, blockTimestamp uint64) CodecVersion {
	if !config.IsBernoulli(new(big.Int).SetUint64(blockHeight)) {
		return CodecV0
	} else if !config.IsCurie(new(big.Int).SetUint64(blockHeight)) {
		return CodecV1
	} else if !config.IsDarwin(blockTimestamp) {
		return CodecV2
	} else if !config.IsDarwinV2(blockTimestamp) {
		return CodecV3
	} else {
		return CodecV4
	}
}

// GetMaxChunksPerBatch returns the maximum number of chunks allowed per batch for the given block height and timestamp.
func GetMaxChunksPerBatch(config *params.ChainConfig, blockHeight, blockTimestamp uint64) uint64 {
	if !config.IsBernoulli(new(big.Int).SetUint64(blockHeight)) {
		return 15
	} else if !config.IsCurie(new(big.Int).SetUint64(blockHeight)) {
		return 15
	} else if !config.IsDarwin(blockTimestamp) {
		return 45
	} else if !config.IsDarwinV2(blockTimestamp) {
		return 45
	} else {
		return 45
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
