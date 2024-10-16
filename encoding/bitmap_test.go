package encoding

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeBitmap(t *testing.T) {
	bitmapHex := "0000000000000000000000000000000000000000000000000000001ffffffbff"
	skippedL1MessageBitmap, err := hex.DecodeString(bitmapHex)
	assert.NoError(t, err)

	decodedBitmap, err := decodeBitmap(skippedL1MessageBitmap, 42)
	assert.NoError(t, err)

	isL1MessageSkipped := func(skippedBitmap []*big.Int, index uint64) bool {
		if index >= uint64(len(skippedBitmap))*256 {
			return false
		}
		quo := index / 256
		rem := index % 256
		return skippedBitmap[quo].Bit(int(rem)) == 1
	}

	assert.True(t, isL1MessageSkipped(decodedBitmap, 0))
	assert.True(t, isL1MessageSkipped(decodedBitmap, 9))
	assert.False(t, isL1MessageSkipped(decodedBitmap, 10))
	assert.True(t, isL1MessageSkipped(decodedBitmap, 11))
	assert.True(t, isL1MessageSkipped(decodedBitmap, 36))
	assert.False(t, isL1MessageSkipped(decodedBitmap, 37))
	assert.False(t, isL1MessageSkipped(decodedBitmap, 38))
	assert.False(t, isL1MessageSkipped(decodedBitmap, 39))
	assert.False(t, isL1MessageSkipped(decodedBitmap, 40))
	assert.False(t, isL1MessageSkipped(decodedBitmap, 41))

	_, err = decodeBitmap([]byte{0x00}, 8)
	assert.Error(t, err)

	_, err = decodeBitmap([]byte{0x00, 0x00, 0x00, 0x00}, 33)
	assert.Error(t, err)
}
