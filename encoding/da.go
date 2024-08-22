package encoding

import (
	"encoding/binary"
	"fmt"
	"math/big"

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
	var totalTxNum uint64
	for _, block := range c.Blocks {
		totalTxNum += block.Header.GasUsed
	}
	return totalTxNum
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

func getTxPayloadLength(txData *types.TransactionData) (uint64, error) {
	rlpTxData, err := ConvertTxDataToRLPEncoding(txData, false /* no mock */)
	if err != nil {
		return 0, err
	}
	return uint64(len(rlpTxData)), nil
}

// GetCodecVersion determines the codec version based on hain configuration, block number, and timestamp.
func GetCodecVersion(chainCfg *params.ChainConfig, startBlockNumber *big.Int, startBlockTimestamp uint64) CodecVersion {
	switch {
	case startBlockNumber.Uint64() == 0 || !chainCfg.IsBernoulli(startBlockNumber):
		return CodecV0 // codecv0: genesis batch or batches before Bernoulli
	case !chainCfg.IsCurie(startBlockNumber):
		return CodecV1 // codecv1: batches after Bernoulli and before Curie
	case !chainCfg.IsDarwin(startBlockTimestamp):
		return CodecV2 // codecv2: batches after Curie and before Darwin
	case !chainCfg.IsDarwinV2(startBlockTimestamp):
		return CodecV3 // codecv3: batches after Darwin
	default:
		return CodecV4 // codecv4: batches after DarwinV2
	}
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
