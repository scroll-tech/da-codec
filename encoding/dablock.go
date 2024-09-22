package encoding

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// DABlockV0 represents a Data Availability Block.
type DABlockV0 struct {
	number          uint64
	timestamp       uint64
	baseFee         *big.Int
	gasLimit        uint64
	numTransactions uint16
	numL1Messages   uint16
}

// NewDABlockV0 is a constructor function for DABlockV0 that initializes the internal fields.
func NewDABlockV0(number uint64, timestamp uint64, baseFee *big.Int, gasLimit uint64, numTransactions uint16, numL1Messages uint16) *DABlockV0 {
	return &DABlockV0{
		number:          number,
		timestamp:       timestamp,
		baseFee:         baseFee,
		gasLimit:        gasLimit,
		numTransactions: numTransactions,
		numL1Messages:   numL1Messages,
	}
}

// Encode serializes the DABlock into a slice of bytes.
func (b *DABlockV0) Encode() []byte {
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
func (b *DABlockV0) Decode(bytes []byte) error {
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
func (b *DABlockV0) Number() uint64 {
	return b.number
}

// Timestamp returns the block timestamp.
func (b *DABlockV0) Timestamp() uint64 {
	return b.timestamp
}

// BaseFee returns the block base fee.
func (b *DABlockV0) BaseFee() *big.Int {
	return b.baseFee
}

// GasLimit returns the block gas limit.
func (b *DABlockV0) GasLimit() uint64 {
	return b.gasLimit
}

// NumTransactions returns the number of transactions in the block.
func (b *DABlockV0) NumTransactions() uint16 {
	return b.numTransactions
}

// NumL1Messages returns the number of L1 messages in the block.
func (b *DABlockV0) NumL1Messages() uint16 {
	return b.numL1Messages
}
