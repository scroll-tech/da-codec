package encoding

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// DABlock represents a Data Availability Block.
type DABlock struct {
	BlockNumber     uint64
	Timestamp       uint64
	BaseFee         *big.Int
	GasLimit        uint64
	NumTransactions uint16
	NumL1Messages   uint16
}

// Encode serializes the DABlock into a slice of bytes.
func (b *DABlock) Encode() []byte {
	bytes := make([]byte, 60)
	binary.BigEndian.PutUint64(bytes[0:], b.BlockNumber)
	binary.BigEndian.PutUint64(bytes[8:], b.Timestamp)
	if b.BaseFee != nil {
		binary.BigEndian.PutUint64(bytes[40:], b.BaseFee.Uint64())
	}
	binary.BigEndian.PutUint64(bytes[48:], b.GasLimit)
	binary.BigEndian.PutUint16(bytes[56:], b.NumTransactions)
	binary.BigEndian.PutUint16(bytes[58:], b.NumL1Messages)
	return bytes
}

// Decode populates the fields of a DABlock from a byte slice.
func (b *DABlock) Decode(bytes []byte) error {
	if len(bytes) != 60 {
		return errors.New("block encoding is not 60 bytes long")
	}

	b.BlockNumber = binary.BigEndian.Uint64(bytes[0:8])
	b.Timestamp = binary.BigEndian.Uint64(bytes[8:16])
	b.BaseFee = new(big.Int).SetUint64(binary.BigEndian.Uint64(bytes[40:48]))
	b.GasLimit = binary.BigEndian.Uint64(bytes[48:56])
	b.NumTransactions = binary.BigEndian.Uint16(bytes[56:58])
	b.NumL1Messages = binary.BigEndian.Uint16(bytes[58:60])

	return nil
}
