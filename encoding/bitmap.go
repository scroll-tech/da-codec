package encoding

import (
	"fmt"
	"math/big"

	"github.com/scroll-tech/go-ethereum/core/types"
)

// constructSkippedBitmap constructs skipped L1 message bitmap of the batch.
func constructSkippedBitmap(batchIndex uint64, chunks []*Chunk, totalL1MessagePoppedBefore uint64) ([]byte, uint64, error) {
	// skipped L1 message bitmap, an array of 256-bit bitmaps
	var skippedBitmap []*big.Int

	// the first queue index that belongs to this batch
	baseIndex := totalL1MessagePoppedBefore

	// the next queue index that we need to process
	nextIndex := totalL1MessagePoppedBefore

	for chunkID, chunk := range chunks {
		for blockID, block := range chunk.Blocks {
			for _, tx := range block.Transactions {
				if tx.Type != types.L1MessageTxType {
					continue
				}

				currentIndex := tx.Nonce

				if currentIndex < nextIndex {
					return nil, 0, fmt.Errorf("unexpected batch payload, expected queue index: %d, got: %d. Batch index: %d, chunk index in batch: %d, block index in chunk: %d, block hash: %v, transaction hash: %v", nextIndex, currentIndex, batchIndex, chunkID, blockID, block.Header.Hash(), tx.TxHash)
				}

				// mark skipped messages
				for skippedIndex := nextIndex; skippedIndex < currentIndex; skippedIndex++ {
					quo := int((skippedIndex - baseIndex) / 256)
					rem := int((skippedIndex - baseIndex) % 256)
					for len(skippedBitmap) <= quo {
						bitmap := big.NewInt(0)
						skippedBitmap = append(skippedBitmap, bitmap)
					}
					skippedBitmap[quo].SetBit(skippedBitmap[quo], rem, 1)
				}

				// process included message
				quo := int((currentIndex - baseIndex) / 256)
				for len(skippedBitmap) <= quo {
					bitmap := big.NewInt(0)
					skippedBitmap = append(skippedBitmap, bitmap)
				}

				nextIndex = currentIndex + 1
			}
		}
	}

	bitmapBytes := make([]byte, len(skippedBitmap)*32)
	for ii, num := range skippedBitmap {
		bytes := num.Bytes()
		padding := 32 - len(bytes)
		copy(bitmapBytes[32*ii+padding:], bytes)
	}

	return bitmapBytes, nextIndex, nil
}

// decodeBitmap decodes skipped L1 message bitmap of the batch from bytes to big.Int's.
func decodeBitmap(skippedL1MessageBitmap []byte, totalL1MessagePopped int) ([]*big.Int, error) {
	length := len(skippedL1MessageBitmap)
	if length%32 != 0 {
		return nil, fmt.Errorf("skippedL1MessageBitmap length doesn't match, skippedL1MessageBitmap length should be equal 0 modulo 32, length of skippedL1MessageBitmap: %v", length)
	}
	if length*8 < totalL1MessagePopped {
		return nil, fmt.Errorf("skippedL1MessageBitmap length is too small, skippedL1MessageBitmap length should be at least %v, length of skippedL1MessageBitmap: %v", (totalL1MessagePopped+7)/8, length)
	}
	var skippedBitmap []*big.Int
	for index := 0; index < length/32; index++ {
		bitmap := big.NewInt(0).SetBytes(skippedL1MessageBitmap[index*32 : index*32+32])
		skippedBitmap = append(skippedBitmap, bitmap)
	}
	return skippedBitmap, nil
}

// isL1MessageSkipped checks if index is skipped in bitmap.
func isL1MessageSkipped(skippedBitmap []*big.Int, index uint64) bool {
	if index > uint64(len(skippedBitmap))*256 {
		return false
	}
	quo := index / 256
	rem := index % 256
	return skippedBitmap[quo].Bit(int(rem)) != 0
}
