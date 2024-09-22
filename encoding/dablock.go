package encoding

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// DABlockImpl represents a Data Availability Block.
type DABlockImpl struct {
	number          uint64
	timestamp       uint64
	baseFee         *big.Int
	gasLimit        uint64
	numTransactions uint16
	numL1Messages   uint16
}

// NewDABlockImpl is a constructor function for DABlockImpl that initializes the internal fields.
func NewDABlockImpl(number uint64, timestamp uint64, baseFee *big.Int, gasLimit uint64, numTransactions uint16, numL1Messages uint16) *DABlockImpl {
	return &DABlockImpl{
		number:          number,
		timestamp:       timestamp,
		baseFee:         baseFee,
		gasLimit:        gasLimit,
		numTransactions: numTransactions,
		numL1Messages:   numL1Messages,
	}
}

// Encode serializes the DABlock into a slice of bytes.
func (b *DABlockImpl) Encode() []byte {
	bytes := make([]byte, BlockContextByteSize)
	binary.BigEndian.PutUint64(bytes[0:], b.number)
	binary.BigEndian.PutUint64(bytes[8:], b.timestamp)
	if b.baseFee != nil {
		binary.BigEndian.PutUint64(bytes[40:], b.baseFee.Uint64())
	}
	binary.BigEndian.PutUint64(bytes[48:], b.gasLimit)
	binary.BigEndian.PutUint16(bytes[56:], b.numTransactions)
	binary.BigEndian.PutUint16(bytes[58:], b.numL1Messages)
	return bytes
}

// Decode populates the fields of a DABlock from a byte slice.
func (b *DABlockImpl) Decode(bytes []byte) error {
	if len(bytes) != BlockContextByteSize {
		return errors.New("block encoding is not BlockContextByteSize bytes long")
	}

	b.number = binary.BigEndian.Uint64(bytes[0:8])
	b.timestamp = binary.BigEndian.Uint64(bytes[8:16])
	b.baseFee = new(big.Int).SetUint64(binary.BigEndian.Uint64(bytes[40:48]))
	b.gasLimit = binary.BigEndian.Uint64(bytes[48:56])
	b.numTransactions = binary.BigEndian.Uint16(bytes[56:58])
	b.numL1Messages = binary.BigEndian.Uint16(bytes[58:60])

	return nil
}

// Number returns the block number.
func (b *DABlockImpl) Number() uint64 {
	return b.number
}

// Timestamp returns the block timestamp.
func (b *DABlockImpl) Timestamp() uint64 {
	return b.timestamp
}

// BaseFee returns the block base fee.
func (b *DABlockImpl) BaseFee() *big.Int {
	return b.baseFee
}

// GasLimit returns the block gas limit.
func (b *DABlockImpl) GasLimit() uint64 {
	return b.gasLimit
}

// NumTransactions returns the number of transactions in the block.
func (b *DABlockImpl) NumTransactions() uint16 {
	return b.numTransactions
}

// NumL1Messages returns the number of L1 messages in the block.
func (b *DABlockImpl) NumL1Messages() uint16 {
	return b.numL1Messages
}
