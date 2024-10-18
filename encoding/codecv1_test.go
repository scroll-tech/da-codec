package encoding

import (
	"encoding/hex"
	"math"
	"strings"
	"testing"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodecV1BlockEncode(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	daBlockV0 := &daBlockV0{}
	encoded := hex.EncodeToString(daBlockV0.Encode())
	assert.Equal(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	daBlock, err := codecv1.NewDABlock(block2, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	daBlock, err = codecv1.NewDABlock(block3, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	daBlock, err = codecv1.NewDABlock(block4, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	daBlock, err = codecv1.NewDABlock(block5, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	daBlock, err = codecv1.NewDABlock(block6, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	daBlock, err = codecv1.NewDABlock(block7, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)

	codecv0, err := CodecFromVersion(CodecV0)
	require.NoError(t, err)

	// sanity check: v0 and v1 block encodings are identical
	for _, block := range []*Block{block2, block3, block4, block5, block6, block7} {
		blockv0, err := codecv0.NewDABlock(block, 0)
		assert.NoError(t, err)
		encodedv0 := hex.EncodeToString(blockv0.Encode())

		blockv1, err := codecv1.NewDABlock(block, 0)
		assert.NoError(t, err)
		encodedv1 := hex.EncodeToString(blockv1.Encode())

		assert.Equal(t, encodedv0, encodedv1)
	}
}

func TestCodecV1ChunkEncode(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	// chunk with a single empty block
	daBlock := &daBlockV0{}
	daChunkV1 := &daChunkV1{blocks: []DABlock{daBlock}, transactions: [][]*types.TransactionData{nil}}

	encodedBytes, err := daChunkV1.Encode()
	assert.NoError(t, err)
	encoded := hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	// transactions are not part of the encoding
	daChunkV1.transactions[0] = append(daChunkV1.transactions[0], &types.TransactionData{Type: types.L1MessageTxType}, &types.TransactionData{Type: types.DynamicFeeTxType})
	encodedBytes, err = daChunkV1.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	originalChunk := &Chunk{Blocks: []*Block{block}}
	daChunk, err := codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)
}

func TestCodecV1ChunkHash(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	// chunk with a single empty block
	daBlock := &daBlockV0{}
	chunk := &daChunkV1{blocks: []DABlock{daBlock}, transactions: [][]*types.TransactionData{nil}}
	hash, err := chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x7cdb9d7f02ea58dfeb797ed6b4f7ea68846e4f2b0e30ed1535fc98b60c4ec809", hash.Hex())

	// L1 transactions are part of the hash
	chunk.transactions[0] = append(chunk.transactions[0], &types.TransactionData{Type: types.L1MessageTxType, TxHash: "0x0000000000000000000000000000000000000000000000000000000000000000"})
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xdcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2", hash.Hex())

	// L2 transactions are not part of the hash
	chunk.transactions[0] = append(chunk.transactions[0], &types.TransactionData{Type: types.DynamicFeeTxType, TxHash: "0x0000000000000000000000000000000000000000000000000000000000000000"})
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xdcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2", hash.Hex())

	// numL1Messages are not part of the hash
	daBlock = chunk.blocks[0].(*daBlockV0)
	daBlock.numL1Messages = 1
	chunk.blocks[0] = daBlock

	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xdcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2", hash.Hex())

	// invalid hash
	chunk.transactions[0] = append(chunk.transactions[0], &types.TransactionData{Type: types.L1MessageTxType, TxHash: "0xg"})
	_, err = chunk.Hash()
	assert.Error(t, err)

	block := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	originalChunk := &Chunk{Blocks: []*Block{block}}
	daChunk, err := codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x820f25d806ddea0ccdbfa463ee480da5b6ea3906e8a658417fb5417d0f837f5c", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x4620b3900e8454133448b677cbb2054c5dd61d467d7ebf752bfb12cffff90f40", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x059c6451e83012b405c7e1a38818369012a4a1c87d7d699366eac946d0410d73", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x854fc3136f47ce482ec85ee3325adfa16a1a1d60126e1c119eaaf0c3a9e90f8e", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x2aa220ca7bd1368e59e8053eb3831e30854aa2ec8bd3af65cee350c1c0718ba6", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv1.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xb65521bea7daff75838de07951c3c055966750fb5a270fead5e0e727c32455c3", hash.Hex())
}

func TestCodecV1BatchEncode(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	// empty batch
	batch := &daBatchV1{
		daBatchV0: daBatchV0{
			version: CodecV1,
		},
	}
	encoded := hex.EncodeToString(batch.Encode())
	assert.Equal(t, "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "010000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101af944924715b48be6ce3c35aef7500a50e909265599bd2b3e544ac59fc75530000000000000000000000000000000000000000000000000000000000000000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "01000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a6010c54fa675ed1b78f269827177019b0814a4ac4d269c68037e2c41cf08f94110000000000000000000000000000000000000000000000000000000000000000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "010000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f01ea66c4de196d36e2c3a5d7c0045100b9e46ef65be8f7a921ef20e6f2e99ebd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ff", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "010000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b401a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffff", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "010000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d01a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001dd", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "01000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d520801a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a60000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0000000000000000000000000000000000000000000000000000000000000000", encoded)

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "010000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8014ae5927a983081a8bcdbcce19e926c9e4c56e2dc89c91c32c034b875b8a1ca00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "010000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e13476701b63f87bdd2caa8d43500d47ee59204f61af95339483c62ff436c6beabf47bf00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)
}

func TestCodecV1BatchHash(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	// empty batch
	batch := &daBatchV1{
		daBatchV0: daBatchV0{
			version: CodecV1,
		},
	}
	assert.Equal(t, common.HexToHash("0x4b6fe410f63051f6e93532087b42ece79fb7b966e2ba5845e6cd1c091f27e564"), batch.Hash())

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xd557b02638c0385d5124f7fc188a025b33f8819b7f78c000751404997148ab8b"), daBatch.Hash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xf13c7e249d00941c59fe4cd970241bbd6753eede8e043c438165674031792b3b"), daBatch.Hash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xb64208f07fab641f7ebf831686d05ad667da0c7bfabcbd9c878cc22cbc8032fd"), daBatch.Hash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x4f7426d164e885574a661838406083f5292b0a1bc6dc20c51129eed0723b8a27"), daBatch.Hash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xfce89ec2aed85cebeb20eea722e3ae4ec622bff49218dbe249a2d358e2e85451"), daBatch.Hash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x8fc063179b709bab338674278bb7b70dce2879a4e11ea857b3a202fb3313559f"), daBatch.Hash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xf1c94cdf45967bc60bfccd599edd8cb07fd0201f41ab068637834f86140f62bf"), daBatch.Hash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xfef0b56bd889529e3a1d884c88dd1c867e084fdc1369496907be8f865f43f0e0"), daBatch.Hash())
}

func TestCodecV1BatchDataHash(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x9f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed541"), daBatch.DataHash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xd46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a6"), daBatch.DataHash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f"), daBatch.DataHash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4"), daBatch.DataHash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d"), daBatch.DataHash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208"), daBatch.DataHash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xe7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8"), daBatch.DataHash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e134767"), daBatch.DataHash())
}

func TestCodecV1CalldataSizeEstimation(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2CalldataSize, err := codecv1.EstimateChunkL1CommitCalldataSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk2CalldataSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2CalldataSize, err := codecv1.EstimateBatchL1CommitCalldataSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch2CalldataSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3CalldataSize, err := codecv1.EstimateChunkL1CommitCalldataSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk3CalldataSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3CalldataSize, err := codecv1.EstimateBatchL1CommitCalldataSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch3CalldataSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4CalldataSize, err := codecv1.EstimateChunkL1CommitCalldataSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk4CalldataSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4CalldataSize, err := codecv1.EstimateBatchL1CommitCalldataSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch4CalldataSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5CalldataSize, err := codecv1.EstimateChunkL1CommitCalldataSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(120), chunk5CalldataSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6CalldataSize, err := codecv1.EstimateChunkL1CommitCalldataSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk6CalldataSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5CalldataSize, err := codecv1.EstimateBatchL1CommitCalldataSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(180), batch5CalldataSize)
}

func TestCodecV1CommitGasEstimation(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2Gas, err := codecv1.EstimateChunkL1CommitGas(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1124), chunk2Gas)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2Gas, err := codecv1.EstimateBatchL1CommitGas(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(157649), batch2Gas)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3Gas, err := codecv1.EstimateChunkL1CommitGas(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1124), chunk3Gas)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3Gas, err := codecv1.EstimateBatchL1CommitGas(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(157649), batch3Gas)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4Gas, err := codecv1.EstimateChunkL1CommitGas(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(3745), chunk4Gas)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4Gas, err := codecv1.EstimateBatchL1CommitGas(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(160302), batch4Gas)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5Gas, err := codecv1.EstimateChunkL1CommitGas(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2202), chunk5Gas)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6Gas, err := codecv1.EstimateChunkL1CommitGas(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(3745), chunk6Gas)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5Gas, err := codecv1.EstimateBatchL1CommitGas(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(163087), batch5Gas)
}

func TestCodecV1BatchSizeAndBlobSizeEstimation(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2BatchBytesSize, chunk2BlobSize, err := codecv1.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(292), chunk2BatchBytesSize)
	assert.Equal(t, uint64(302), chunk2BlobSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2BatchBytesSize, batch2BlobSize, err := codecv1.EstimateBatchL1CommitBatchSizeAndBlobSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(292), batch2BatchBytesSize)
	assert.Equal(t, uint64(302), batch2BlobSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3BatchBytesSize, chunk3BlobSize, err := codecv1.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5743), chunk3BatchBytesSize)
	assert.Equal(t, uint64(5929), chunk3BlobSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3BatchBytesSize, batch3BlobSize, err := codecv1.EstimateBatchL1CommitBatchSizeAndBlobSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5743), batch3BatchBytesSize)
	assert.Equal(t, uint64(5929), batch3BlobSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4BatchBytesSize, chunk4BlobSize, err := codecv1.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(94), chunk4BatchBytesSize)
	assert.Equal(t, uint64(98), chunk4BlobSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	blob4BatchBytesSize, batch4BlobSize, err := codecv1.EstimateBatchL1CommitBatchSizeAndBlobSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(94), blob4BatchBytesSize)
	assert.Equal(t, uint64(98), batch4BlobSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5BatchBytesSize, chunk5BlobSize, err := codecv1.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5973), chunk5BatchBytesSize)
	assert.Equal(t, uint64(6166), chunk5BlobSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6BatchBytesSize, chunk6BlobSize, err := codecv1.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(94), chunk6BatchBytesSize)
	assert.Equal(t, uint64(98), chunk6BlobSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5BatchBytesSize, batch5BlobSize, err := codecv1.EstimateBatchL1CommitBatchSizeAndBlobSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6005), batch5BatchBytesSize)
	assert.Equal(t, uint64(6199), batch5BlobSize)
}

func TestCodecV1BatchL1MessagePopped(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).totalL1MessagePopped)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).totalL1MessagePopped)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV1).totalL1MessagePopped)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 37
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), daBatch.(*daBatchV1).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), daBatch.(*daBatchV1).l1MessagePopped) // skip 7, include 3
	assert.Equal(t, uint64(10), daBatch.(*daBatchV1).totalL1MessagePopped)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(257), daBatch.(*daBatchV1).l1MessagePopped) // skip 255, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV1).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 1
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(256), daBatch.(*daBatchV1).l1MessagePopped) // skip 254, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV1).totalL1MessagePopped)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}} // queue index 10
	chunk9 := &Chunk{Blocks: []*Block{block5}}                 // queue index 37-41
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 10
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(32), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)
}

func TestCodecV1BlobEncodingAndHashing(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	batch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded := strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, // metadata
		"00"+"0001"+"000000e6"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00"+"00"+"000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+"00000000"+
			// tx payload
			"00f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb000ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf670081e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce6400d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e830007a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14a00f60000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde2007e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68483599600fc3f879380aac1c09c6eed32f1", encoded)
	assert.Equal(t, common.HexToHash("0x01af944924715b48be6ce3c35aef7500a50e909265599bd2b3e544ac59fc7553"), batch.(*daBatchV1).blobVersionedHash)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "000001000016310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002f9162d82cf5502843b9b0a17843b9b0a17831197e28080b915d26080604000523480156200001157600080fd5b50604051620014b2380380620014b283390081810160405260a08110156200003757600080fd5b8151602083015160408000850180519151939592948301929184640100000000821115620000635760000080fd5b9083019060208201858111156200007957600080fd5b8251640100000000008111828201881017156200009457600080fd5b8252508151602091820100929091019080838360005b83811015620000c357818101518382015260200100620000a9565b50505050905090810190601f168015620000f1578082038051006001836020036101000a031916815260200191505b5060405260200180516000405193929190846401000000008211156200011557600080fd5b908301906000208201858111156200012b57600080fd5b8251640100000000811182820188001017156200014657600080fd5b8252508151602091820192909101908083830060005b83811015620001755781810151838201526020016200015b565b5050005050905090810190601f168015620001a3578082038051600183602003610100000a031916815260200191505b506040526020908101518551909350859250008491620001c8916003918501906200026b565b508051620001de906004906000208401906200026b565b50506005805461ff001960ff199091166012171690005550600680546001600160a01b038088166001600160a01b031992831617900092556007805492871692909116919091179055620002308162000255565b5000506005805462010000600160b01b031916336201000002179055506200030700915050565b6005805460ff191660ff92909216919091179055565b82805460000181600116156101000203166002900490600052602060002090601f01602000900481019282601f10620002ae57805160ff1916838001178555620002de56005b82800160010185558215620002de579182015b82811115620002de57825100825591602001919060010190620002c1565b50620002ec929150620002f056005b5090565b5b80821115620002ec5760008155600101620002f1565b61119b0080620003176000396000f3fe608060405234801561001057600080fd5b50600004361061010b5760003560e01c80635c975abb116100a257806395d89b41110061007157806395d89b41146103015780639dc29fac14610309578063a457c200d714610335578063a9059cbb14610361578063dd62ed3e1461038d5761010b00565b80635c975abb1461029d57806370a08231146102a55780638456cb5914006102cb5780638e50817a146102d35761010b565b8063313ce567116100de57008063313ce5671461021d578063395093511461023b5780633f4ba83a146102006757806340c10f19146102715761010b565b806306fdde031461011057806300095ea7b31461018d57806318160ddd146101cd57806323b872dd146101e757005b600080fd5b6101186103bb565b604080516020808252835181830152835100919283929083019185019080838360005b838110156101525781810151838200015260200161013a565b50505050905090810190601f16801561017f578082000380516001836020036101000a031916815260200191505b50925050506040005180910390f35b6101b9600480360360408110156101a357600080fd5b50600001600160a01b038135169060200135610451565b60408051911515825251900081900360200190f35b6101d561046e565b6040805191825251908190036020000190f35b6101b9600480360360608110156101fd57600080fd5b50600160010060a01b03813581169160208101359091169060400135610474565b610225610004fb565b6040805160ff9092168252519081900360200190f35b6101b9600400803603604081101561025157600080fd5b506001600160a01b03813516906000200135610504565b61026f610552565b005b61026f600480360360408110150061028757600080fd5b506001600160a01b0381351690602001356105a9565b006101b9610654565b6101d5600480360360208110156102bb57600080fd5b5000356001600160a01b0316610662565b61026f61067d565b61026f60048036030060408110156102e957600080fd5b506001600160a01b0381358116916020010035166106d2565b610118610757565b61026f6004803603604081101561031f0057600080fd5b506001600160a01b0381351690602001356107b8565b6101b9006004803603604081101561034b57600080fd5b506001600160a01b0381351600906020013561085f565b6101b96004803603604081101561037757600080fd005b506001600160a01b0381351690602001356108c7565b6101d560048036030060408110156103a357600080fd5b506001600160a01b0381358116916020010035166108db565b60038054604080516020601f600260001961010060018816001502019095169490940493840181900481028201810190925282815260609300909290918301828280156104475780601f1061041c5761010080835404028300529160200191610447565b820191906000526020600020905b8154815290600001019060200180831161042a57829003601f168201915b505050505090509000565b600061046561045e610906565b848461090a565b50600192915050565b0060025490565b60006104818484846109f6565b6104f18461048d610906565b006104ec8560405180606001604052806028815260200161108560289139600100600160a01b038a166000908152600160205260408120906104cb610906565b006001600160a01b031681526020810191909152604001600020549190610b5100565b61090a565b5060019392505050565b60055460ff1690565b600061046500610511610906565b846104ec8560016000610522610906565b6001600160a0001b03908116825260208083019390935260409182016000908120918c16815200925290205490610be8565b6007546001600160a01b0316331461059f57604000805162461bcd60e51b815260206004820152600b60248201526a1b9bdd0818005b1b1bddd95960aa1b604482015290519081900360640190fd5b6105a7610c0049565b565b600554610100900460ff16156105f9576040805162461bcd60e5001b815260206004820152601060248201526f14185d5cd8589b194e881c185d005cd95960821b604482015290519081900360640190fd5b600654600160016000a01b03163314610646576040805162461bcd60e51b81526020600482015260000b60248201526a1b9bdd08185b1b1bddd95960aa1b60448201529051908190000360640190fd5b6106508282610ced565b5050565b600554610100900460ff001690565b6001600160a01b031660009081526020819052604090205490565b006007546001600160a01b031633146106ca576040805162461bcd60e51b81520060206004820152600b60248201526a1b9bdd08185b1b1bddd95960aa1b60440082015290519081900360640190fd5b6105a7610ddd565b600554620100009000046001600160a01b03163314610726576040805162461bcd60e51b81526020006004820152600c60248201526b6f6e6c7920466163746f727960a01b60448200015290519081900360640190fd5b600780546001600160a01b03928316600100600160a01b0319918216179091556006805493909216921691909117905556005b60048054604080516020601f600260001961010060018816150201909516009490940493840181900481028201810190925282815260609390929091830100828280156104475780601f1061041c5761010080835404028352916020019100610447565b600554610100900460ff1615610808576040805162461bcd60e5001b815260206004820152601060248201526f14185d5cd8589b194e881c185d005cd95960821b604482015290519081900360640190fd5b600654600160016000a01b03163314610855576040805162461bcd60e51b81526020600482015260000b60248201526a1b9bdd08185b1b1bddd95960aa1b60448201529051908190000360640190fd5b6106508282610e65565b600061046561086c610906565b84006104ec85604051806060016040528060258152602001611117602591396001006000610896610906565b6001600160a01b0390811682526020808301939093005260409182016000908120918d16815292529020549190610b51565b6000610004656108d4610906565b84846109f6565b6001600160a01b0391821660009000815260016020908152604080832093909416825291909152205490565b339000565b6001600160a01b03831661094f5760405162461bcd60e51b8152600401008080602001828103825260248152602001806110f3602491396040019150500060405180910390fd5b6001600160a01b0382166109945760405162461bcd6000e51b815260040180806020018281038252602281526020018061103d602291003960400191505060405180910390fd5b6001600160a01b038084166000818100526001602090815260408083209487168084529482529182902085905581510085815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b00200ac8c7c3b9259281900390910190a3505050565b6001600160a01b03831600610a3b5760405162461bcd60e51b8152600401808060200182810382526025008152602001806110ce6025913960400191505060405180910390fd5b600160000160a01b038216610a805760405162461bcd60e51b815260040180806020010082810382526023815260200180610ff8602391396040019150506040518091000390fd5b610a8b838383610f61565b610ac8816040518060600160405280600026815260200161105f602691396001600160a01b038616600090815260208100905260409020549190610b51565b6001600160a01b03808516600090815260002081905260408082209390935590841681522054610af79082610be8565b600001600160a01b03808416600081815260208181526040918290209490945580005185815290519193928716927fddf252ad1be2c89b69c2b068fc378daa952b00a7f163c4a11628f55a4df523b3ef92918290030190a3505050565b6000818400841115610be05760405162461bcd60e51b8152600401808060200182810382005283818151815260200191508051906020019080838360005b83811015610b00a5578181015183820152602001610b8d565b50505050905090810190601f16008015610bd25780820380516001836020036101000a03191681526020019150005b509250505060405180910390fd5b505050900390565b60008282018381100015610c42576040805162461bcd60e51b815260206004820152601b6024820100527f536166654d6174683a206164646974696f6e206f766572666c6f77000000000000604482015290519081900360640190fd5b9392505050565b60055461000100900460ff16610c9c576040805162461bcd60e51b81526020600482015200601460248201527314185d5cd8589b194e881b9bdd081c185d5cd95960621b00604482015290519081900360640190fd5b6005805461ff00191690557f5db900ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa61000cd0610906565b604080516001600160a01b03909216825251908190036020000190a1565b6001600160a01b038216610d48576040805162461bcd60e51b81005260206004820152601f60248201527f45524332303a206d696e7420746f2000746865207a65726f20616464726573730060448201529051908190036064010090fd5b610d5460008383610f61565b600254610d619082610be8565b600255006001600160a01b038216600090815260208190526040902054610d87908261000be8565b6001600160a01b038316600081815260208181526040808320949000945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa95002ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b60055400610100900460ff1615610e2d576040805162461bcd60e51b81526020600482000152601060248201526f14185d5cd8589b194e881c185d5cd95960821b60440082015290519081900360640190fd5b6005805461ff0019166101001790557f0062e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a20058610cd0610906565b6001600160a01b038216610eaa5760405162461bcd6000e51b81526004018080602001828103825260218152602001806110ad602191003960400191505060405180910390fd5b610eb682600083610f61565b610ef3008160405180606001604052806022815260200161101b60229139600160016000a01b0385166000908152602081905260409020549190610b51565b600160010060a01b038316600090815260208190526040902055600254610f199082610f00b5565b6002556040805182815290516000916001600160a01b038516917fdd00f252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef009181900360200190a35050565b610f6c838383610fb0565b610f7461065456005b15610fb05760405162461bcd60e51b81526004018080602001828103825200602a81526020018061113c602a913960400191505060405180910390fd5b50005050565b6000610c4283836040518060400160405280601e81526020017f53006166654d6174683a207375627472616374696f6e206f766572666c6f77000000815250610b5156fe45524332303a207472616e7366657220746f2074686520007a65726f206164647265737345524332303a206275726e20616d6f756e742000657863656564732062616c616e636545524332303a20617070726f76652074006f20746865207a65726f206164647265737345524332303a207472616e736600657220616d6f756e7420657863656564732062616c616e636545524332303a00207472616e7366657220616d6f756e74206578636565647320616c6c6f7761006e636545524332303a206275726e2066726f6d20746865207a65726f20616400647265737345524332303a207472616e736665722066726f6d20746865207a0065726f206164647265737345524332303a20617070726f76652066726f6d2000746865207a65726f206164647265737345524332303a206465637265617365006420616c6c6f77616e63652062656c6f77207a65726f4552433230506175730061626c653a20746f6b656e207472616e73666572207768696c652070617573006564a2646970667358221220e96342bec8f6c2bf72815a39998973b64c3bed0057770f402e9a7b7eeda0265d4c64736f6c634300060c0033000000000000000000000000001c5a77d9fa7ef466951b2f01f724bca3a5820b63000000000000000000000000001c5a77d9fa7ef466951b2f01f724bca3a5820b630000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000009570045544820636f696e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004574554480000000000000000000000000000000000000000000000000000000000c001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e173700f0553c633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bd00a52095d44b8a9af7", encoded)
	assert.Equal(t, common.HexToHash("0x010c54fa675ed1b78f269827177019b0814a4ac4d269c68037e2c41cf08f9411"), batch.(*daBatchV1).blobVersionedHash)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0000010000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000df0b80825dc0941a258d17bf244c4df02d40343a7626a9d321e10580808080008", encoded)
	assert.Equal(t, common.HexToHash("0x01ea66c4de196d36e2c3a5d7c0045100b9e46ef65be8f7a921ef20e6f2e99ebd"), batch.(*daBatchV1).blobVersionedHash)

	// this batch only contains L1 txs
	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "000001", encoded)
	assert.Equal(t, common.HexToHash("0x01a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a6"), batch.(*daBatchV1).blobVersionedHash)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "000001", encoded)
	assert.Equal(t, common.HexToHash("0x01a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a6"), batch.(*daBatchV1).blobVersionedHash)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "000001", encoded)
	assert.Equal(t, common.HexToHash("0x01a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a6"), batch.(*daBatchV1).blobVersionedHash)

	// 15 chunks
	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, // metadata
		"00"+"000f"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"00"+"00"+"0000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+"000000e6"+
			// tx payload
			"00f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb000ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf670081e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce6400d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e830007a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14a00f60000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde2007e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68483599600fc3f879380aac1c09c6eed32f1f87180843b9aec2e8307a12094c0c4c8baea003f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019ece00a0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86d00f514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288b00baf42a8bf87101843b9aec2e8307a1209401bae6bf68e9a03fb2bc0615b1bf000d69ce9411ed8a152d02c7e14af60000008083019ecea0f039985866d8256f0010c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f002b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f1f87180843b009aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d0002c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b00219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c4d199600b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e8307a120940100bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14af6000000800083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde27e2604393e00b095b7f77316a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f87938000aac1c09c6eed32f1f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b600e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae9900c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a034cb00d19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8007101843b9aec2e8307a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce941100ed8a152d02c7e14af60000008083019ecea0f039985866d8256f10c1be4f7b002cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec005bd4aba684835996fc3f879380aac1c09c6eed32f1f87180843b9aec2e830700a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de10200513d56548a41e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c57008fd7f51bfaec288bbaf42a8bf87101843b9aec2e8307a1209401bae6bf68e900a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14af60000008083019ecea000f039985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f7730016a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6e00ed32f1f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2ade00ceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7b00a5cf6781e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd7300e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9a00ec2e8307a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d0200c7e14af60000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f0020bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68400835996fc3f879380aac1c09c6eed32f1f87180843b9aec2e8307a12094c0c400c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808300019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a0041e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfa00ec288bbaf42a8bf87101843b9aec2e8307a1209401bae6bf68e9a03fb2bc060015b1bf0d69ce9411ed8a152d02c7e14af60000008083019ecea0f03998586600d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e0081065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f1f8710080843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca2008a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e9000cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c004d1996b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e8307a100209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14af6000000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde27e260004393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f00879380aac1c09c6eed32f1f87180843b9aec2e8307a12094c0c4c8baea3f6a00cb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab0007ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df51400a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf4002a8bf87101843b9aec2e8307a1209401bae6bf68e9a03fb2bc0615b1bf0d6900ce9411ed8a152d02c7e14af60000008083019ecea0f039985866d8256f10c100be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b460004bcec5bd4aba684835996fc3f879380aac1c09c6eed32f1f87180843b9aec002e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c700e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b001de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c4d1996b9b500243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e8307a1209401bae600bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14af6000000808301009ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb09500b7f77316a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac100c09c6eed32f1f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb009e2adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67a00a78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a034cbd19f00eacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8710100843b9aec2e8307a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a00152d02c7e14af60000008083019ecea0f039985866d8256f10c1be4f7b2cac00e28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd400aba684835996fc3f879380aac1c09c6eed32f1f87180843b9aec2e8307a1200094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d0056548a41e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd700f51bfaec288bbaf42a8bf87101843b9aec2e8307a1209401bae6bf68e9a03f00b2bc0615b1bf0d69ce9411ed8a152d02c7e14af60000008083019ecea0f03900985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a0005a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed3200f1f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceea00cb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf006781e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce0064d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e008307a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e1004af60000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bd00e27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68483590096fc3f879380aac1c09c6eed32f1f87180843b9aec2e8307a12094c0c4c8ba00ea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019e00cea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e8006df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec28008bbaf42a8bf87101843b9aec2e8307a1209401bae6bf68e9a03fb2bc0615b100bf0d69ce9411ed8a152d02c7e14af60000008083019ecea0f039985866d825006f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e8106005f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f1f8718084003b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a15002d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90cc3002b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c4d190096b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e8307a120940001bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14af6000000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde27e260439003eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f87930080aac1c09c6eed32f1", encoded)
	assert.Equal(t, common.HexToHash("0x01521b20f341588dea5978efb00d7b077a986598a6001fc2e5859d77f3ffc284"), batch.(*daBatchV1).blobVersionedHash)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	batch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0000020000173700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb000ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf670081e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce6400d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf87101843b9aec2e830007a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14a00f60000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde2007e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68483599600fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a17843b9b0a1700831197e28080b915d260806040523480156200001157600080fd5b5060405100620014b2380380620014b2833981810160405260a0811015620000375760000080fd5b81516020830151604080850180519151939592948301929184640100000000008211156200006357600080fd5b908301906020820185811115620000007957600080fd5b8251640100000000811182820188101715620000945760000080fd5b82525081516020918201929091019080838360005b8381101562000000c3578181015183820152602001620000a9565b50505050905090810190601f00168015620000f15780820380516001836020036101000a03191681526020010091505b5060405260200180516040519392919084640100000000821115620000011557600080fd5b9083019060208201858111156200012b57600080fd5b8200516401000000008111828201881017156200014657600080fd5b8252508151006020918201929091019080838360005b8381101562000175578181015183820001526020016200015b565b50505050905090810190601f168015620001a3570080820380516001836020036101000a031916815260200191505b506040526000209081015185519093508592508491620001c8916003918501906200026b56005b508051620001de9060049060208401906200026b565b50506005805461ff00001960ff1990911660121716905550600680546001600160a01b03808816600001600160a01b031992831617909255600780549287169290911691909117900055620002308162000255565b50506005805462010000600160b01b031916330062010000021790555062000307915050565b6005805460ff191660ff9290920016919091179055565b82805460018160011615610100020316600290049060000052602060002090601f016020900481019282601f10620002ae57805160ff001916838001178555620002de565b82800160010185558215620002de57918200015b82811115620002de578251825591602001919060010190620002c1565b0050620002ec929150620002f0565b5090565b5b80821115620002ec576000810055600101620002f1565b61119b80620003176000396000f3fe60806040523400801561001057600080fd5b506004361061010b5760003560e01c80635c975a00bb116100a257806395d89b411161007157806395d89b41146103015780639d00c29fac14610309578063a457c2d714610335578063a9059cbb1461036157800063dd62ed3e1461038d5761010b565b80635c975abb1461029d57806370a0820031146102a55780638456cb59146102cb5780638e50817a146102d35761010b00565b8063313ce567116100de578063313ce5671461021d57806339509351140061023b5780633f4ba83a1461026757806340c10f19146102715761010b565b00806306fdde0314610110578063095ea7b31461018d57806318160ddd14610100cd57806323b872dd146101e7575b600080fd5b6101186103bb565b604080510060208082528351818301528351919283929083019185019080838360005b830081101561015257818101518382015260200161013a565b5050505090509081000190601f16801561017f5780820380516001836020036101000a03191681520060200191505b509250505060405180910390f35b6101b960048036036040810010156101a357600080fd5b506001600160a01b03813516906020013561045100565b604080519115158252519081900360200190f35b6101d561046e565b6000408051918252519081900360200190f35b6101b960048036036060811015610001fd57600080fd5b506001600160a01b0381358116916020810135909116900060400135610474565b6102256104fb565b6040805160ff909216825251908100900360200190f35b6101b96004803603604081101561025157600080fd5b50006001600160a01b038135169060200135610504565b61026f610552565b005b0061026f6004803603604081101561028757600080fd5b506001600160a01b030081351690602001356105a9565b6101b9610654565b6101d560048036036020008110156102bb57600080fd5b50356001600160a01b0316610662565b61026f0061067d565b61026f600480360360408110156102e957600080fd5b50600160000160a01b03813581169160200135166106d2565b610118610757565b61026f006004803603604081101561031f57600080fd5b506001600160a01b038135160090602001356107b8565b6101b96004803603604081101561034b57600080fd005b506001600160a01b03813516906020013561085f565b6101b9600480360300604081101561037757600080fd5b506001600160a01b038135169060200135006108c7565b6101d5600480360360408110156103a357600080fd5b50600160000160a01b03813581169160200135166108db565b6003805460408051602060001f6002600019610100600188161502019095169490940493840181900481020082018101909252828152606093909290918301828280156104475780601f100061041c57610100808354040283529160200191610447565b82019190600052006020600020905b81548152906001019060200180831161042a57829003601f00168201915b5050505050905090565b600061046561045e610906565b84846100090a565b50600192915050565b60025490565b60006104818484846109f656005b6104f18461048d610906565b6104ec8560405180606001604052806028810052602001611085602891396001600160a01b038a16600090815260016020520060408120906104cb610906565b6001600160a01b03168152602081019190910052604001600020549190610b51565b61090a565b5060019392505050565b6000055460ff1690565b6000610465610511610906565b846104ec856001600061000522610906565b6001600160a01b0390811682526020808301939093526040009182016000908120918c168152925290205490610be8565b600754600160010060a01b0316331461059f576040805162461bcd60e51b81526020600482015200600b60248201526a1b9bdd08185b1b1bddd95960aa1b60448201529051908100900360640190fd5b6105a7610c49565b565b600554610100900460ff1615610005f9576040805162461bcd60e51b815260206004820152601060248201526f0014185d5cd8589b194e881c185d5cd95960821b60448201529051908190036000640190fd5b6006546001600160a01b03163314610646576040805162461bcd0060e51b815260206004820152600b60248201526a1b9bdd08185b1b1bddd9590060aa1b604482015290519081900360640190fd5b6106508282610ced565b500050565b600554610100900460ff1690565b6001600160a01b03166000908152006020819052604090205490565b6007546001600160a01b031633146106ca57006040805162461bcd60e51b815260206004820152600b60248201526a1b9bdd0008185b1b1bddd95960aa1b604482015290519081900360640190fd5b6105a700610ddd565b6005546201000090046001600160a01b0316331461072657604000805162461bcd60e51b815260206004820152600c60248201526b6f6e6c792000466163746f727960a01b604482015290519081900360640190fd5b60078054006001600160a01b039283166001600160a01b0319918216179091556006805400939092169216919091179055565b60048054604080516020601f600260001900610100600188161502019095169490940493840181900481028201810190920052828152606093909290918301828280156104475780601f1061041c5761010000808354040283529160200191610447565b600554610100900460ff161561000808576040805162461bcd60e51b815260206004820152601060248201526f0014185d5cd8589b194e881c185d5cd95960821b60448201529051908190036000640190fd5b6006546001600160a01b03163314610855576040805162461bcd0060e51b815260206004820152600b60248201526a1b9bdd08185b1b1bddd9590060aa1b604482015290519081900360640190fd5b6106508282610e65565b60000061046561086c610906565b846104ec85604051806060016040528060258100526020016111176025913960016000610896610906565b6001600160a01b0300908116825260208083019390935260409182016000908120918d1681529252009020549190610b51565b60006104656108d4610906565b84846109f6565b600001600160a01b0391821660009081526001602090815260408083209390941600825291909152205490565b3390565b6001600160a01b03831661094f576040005162461bcd60e51b8152600401808060200182810382526024815260200180006110f36024913960400191505060405180910390fd5b6001600160a01b038200166109945760405162461bcd60e51b81526004018080602001828103825260002281526020018061103d6022913960400191505060405180910390fd5b600100600160a01b0380841660008181526001602090815260408083209487168084005294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f7142007d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9259281900390910190a350500050565b6001600160a01b038316610a3b5760405162461bcd60e51b8152600400018080602001828103825260258152602001806110ce602591396040019150005060405180910390fd5b6001600160a01b038216610a805760405162461bcd0060e51b8152600401808060200182810382526023815260200180610ff8602300913960400191505060405180910390fd5b610a8b838383610f61565b610ac8008160405180606001604052806026815260200161105f60269139600160016000a01b0386166000908152602081905260409020549190610b51565b600160010060a01b03808516600090815260208190526040808220939093559084168152002054610af79082610be8565b6001600160a01b03808416600081815260208100815260409182902094909455805185815290519193928716927fddf252ad1b00e2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9291829000030190a3505050565b60008184841115610be05760405162461bcd60e51b810052600401808060200182810382528381815181526020019150805190602001009080838360005b83811015610ba5578181015183820152602001610b8d565b0050505050905090810190601f168015610bd2578082038051600183602003610001000a031916815260200191505b509250505060405180910390fd5b50505000900390565b600082820183811015610c42576040805162461bcd60e51b81520060206004820152601b60248201527f536166654d6174683a20616464697469006f6e206f766572666c6f77000000000060448201529051908190036064019000fd5b9392505050565b600554610100900460ff16610c9c576040805162461b00cd60e51b815260206004820152601460248201527314185d5cd8589b194e88001b9bdd081c185d5cd95960621b604482015290519081900360640190fd5b600005805461ff00191690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a500e8aa4e537bd38aeae4b073aa610cd0610906565b604080516001600160a01b00039092168252519081900360200190a1565b6001600160a01b038216610d4800576040805162461bcd60e51b815260206004820152601f60248201527f4552004332303a206d696e7420746f20746865207a65726f20616464726573730060004482015290519081900360640190fd5b610d5460008383610f61565b60025400610d619082610be8565b6002556001600160a01b03821660009081526020810090526040902054610d879082610be8565b6001600160a01b038316600081810052602081815260408083209490945583518581529351929391927fddf252ad001be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef928190000390910190a35050565b600554610100900460ff1615610e2d57604080516200461bcd60e51b815260206004820152601060248201526f14185d5cd8589b19004e881c185d5cd95960821b604482015290519081900360640190fd5b600580005461ff0019166101001790557f62e78cea01bee320cd4e420270b5ea74000d0011b0c9f74754ebdbfc544b05a258610cd0610906565b6001600160a01b03820016610eaa5760405162461bcd60e51b8152600401808060200182810382526000218152602001806110ad6021913960400191505060405180910390fd5b610e00b682600083610f61565b610ef3816040518060600160405280602281526020000161101b602291396001600160a01b038516600090815260208190526040900020549190610b51565b6001600160a01b03831660009081526020819052604000902055600254610f199082610fb5565b600255604080518281529051600091006001600160a01b038516917fddf252ad1be2c89b69c2b068fc378daa952ba700f163c4a11628f55a4df523b3ef9181900360200190a35050565b610f6c83830083610fb0565b610f74610654565b15610fb05760405162461bcd60e51b81520060040180806020018281038252602a81526020018061113c602a91396040010091505060405180910390fd5b505050565b6000610c428383604051806040010060405280601e81526020017f536166654d6174683a20737562747261637469006f6e206f766572666c6f770000815250610b5156fe45524332303a20747261006e7366657220746f20746865207a65726f206164647265737345524332303a00206275726e20616d6f756e7420657863656564732062616c616e63654552430032303a20617070726f766520746f20746865207a65726f20616464726573730045524332303a207472616e7366657220616d6f756e742065786365656473200062616c616e636545524332303a207472616e7366657220616d6f756e7420650078636565647320616c6c6f77616e636545524332303a206275726e2066726f006d20746865207a65726f206164647265737345524332303a207472616e73660065722066726f6d20746865207a65726f206164647265737345524332303a2000617070726f76652066726f6d20746865207a65726f20616464726573734552004332303a2064656372656173656420616c6c6f77616e63652062656c6f7720007a65726f45524332305061757361626c653a20746f6b656e207472616e7366006572207768696c6520706175736564a2646970667358221220e96342bec8f600c2bf72815a39998973b64c3bed57770f402e9a7b7eeda0265d4c64736f6c63004300060c00330000000000000000000000001c5a77d9fa7ef466951b2f01f70024bca3a5820b630000000000000000000000001c5a77d9fa7ef466951b2f0100f724bca3a5820b630000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000000095745544820636f696e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004574554480000000000000000000000000000000000000000000000000000000000c001a0235c1a8d40e8c347890397f1a9002e6eadbd6422cf7c210e3e1737f0553c633172a02f7c0384ddd06970446e7400229cd96216da62196dc62395bda52095d44b8a9af7df0b80825dc0941a258d0017bf244c4df02d40343a7626a9d321e105808080808", encoded)
	assert.Equal(t, common.HexToHash("0x01b63f87bdd2caa8d43500d47ee59204f61af95339483c62ff436c6beabf47bf"), batch.(*daBatchV1).blobVersionedHash)
}

func TestCodecV1BatchBlobDataProofForPointEvaluation(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err := daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "0d8e67f882c61159aa99b04ec4f6f3d90cb95cbfba6efd56cefc55ca15b290ef423dc493f1dd7c9fbecdffa021ca4649b13e8d72231487034ec6b27e155ecfd7b44a38af1f9a6c70cd3ccfbf71968f447aa566bbafb0bbc566fc9eeb42973484802635a1bbd8305d34a46693331bf607b38542ec811c92d86ff6f3319de06ee60c42655278ccf874f3615f450de730895276828b73db03c553b0bc7e5474a5e0", hex.EncodeToString(verifyData))

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "32da228f4945de828954675f9396debb169bbf336ba93f849a8fc7fee1bc9e5821975f318babe50be728f9b52754d5ce2caa2ba82ba35b5888af1c5f28d23206b8aab265dc352e352807a298f7bb99d432c7cd543e63158cbdb8fbf99f3182a71af35ccbed2693c5e0bc5be38d565e868e0c6fe7bd39baa5ee6339cd334a18af7c680d24e825262499e83b31633b13a9ee89813fae8441630c82bc9dce3f1e07", hex.EncodeToString(verifyData))

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "09a37ab43d41bcae3000c090a341e4661a8dc705b3c93d01b9eda3a0b3f8d4a8088a01e54e3565d2e91ce6afbadf479330847d9106737875303ce17f17c48722afd4e1c55a17dbdf8390b5736158afe238d82f8b696669ba47015fcdfd4d1becd0ff7a47f8f379a4ac8d1741e2d67624aee03a0f7cdb7807bc7e0b9fb20bc299af2a35e38cda816708b40f2f18db491e14a0f5d9cfe2f4c12e4ca1a219484f17", hex.EncodeToString(verifyData))

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "17c71700d949f82963d3bd6af3994ecc383a3d58007f2f27702758fefa34a925304817c2a9ec97b4cfdfc7a646f4bd5ac309e967465bb49059d397094e57cd088f26f349339c68b33ce856aa2c05b8f89e7c23db0c00817550679998efcbd8f2464f9e1ea6c3172b0b750603d1e4ea38979341a25ec6b613f9f32b23fc0e1a11342bc84d4af0705c666e7813de790d0e63b0a9bc56dc484590728aaaafa6b7a4", hex.EncodeToString(verifyData))

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "17c71700d949f82963d3bd6af3994ecc383a3d58007f2f27702758fefa34a925304817c2a9ec97b4cfdfc7a646f4bd5ac309e967465bb49059d397094e57cd088f26f349339c68b33ce856aa2c05b8f89e7c23db0c00817550679998efcbd8f2464f9e1ea6c3172b0b750603d1e4ea38979341a25ec6b613f9f32b23fc0e1a11342bc84d4af0705c666e7813de790d0e63b0a9bc56dc484590728aaaafa6b7a4", hex.EncodeToString(verifyData))

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "17c71700d949f82963d3bd6af3994ecc383a3d58007f2f27702758fefa34a925304817c2a9ec97b4cfdfc7a646f4bd5ac309e967465bb49059d397094e57cd088f26f349339c68b33ce856aa2c05b8f89e7c23db0c00817550679998efcbd8f2464f9e1ea6c3172b0b750603d1e4ea38979341a25ec6b613f9f32b23fc0e1a11342bc84d4af0705c666e7813de790d0e63b0a9bc56dc484590728aaaafa6b7a4", hex.EncodeToString(verifyData))

	// 15 chunks
	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "55dac3baa818133cfdce0f97ddbb950e341399756d7b49bc34107dd65ecd3a4b54d28f1479467d8b97fb99f5257d3e5d63a81cb2d60e3564fe6ec6066a311c119743324c70e20042de6480f115b215fbba3472a8b994303a99576c1244aa4aec22fdfe6c74ec728aa28a9eb3812bc932a0b603cc94be2007d4b3b17af06b4fb30caf0e574d5abcfc5654079e65154679afad75844396082a7200a4e82462aeed", hex.EncodeToString(verifyData))

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "0b14dce4abfdeb3a69a341f7db6b1e16162c20826e6d964a829e20f671030cab35b73ddb4a78fc4a8540f1d8259512c46e606a701e7ef7742e38cc4562ef53b983bee97f95fbf2d789a8e0fb365c26e141d6a31e43403b4a469d1723128f6d5de5c54e913e143feede32d0af9b6fd6fda28e5610ca6b185d6ac30b53bd83d6366fccb1956daafa90ff6b504a966b119ebb45cb3f7085b7c1d622ee1ad27fcff9", hex.EncodeToString(verifyData))
}

func TestCodecV1DecodeDAChunksRawTx(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	block0 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	block1 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk0 := &Chunk{Blocks: []*Block{block0, block1}}
	daChunk0, err := codecv1.NewDAChunk(chunk0, 0)
	assert.NoError(t, err)
	chunkBytes0, err := daChunk0.Encode()
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	block3 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk1 := &Chunk{Blocks: []*Block{block2, block3}}
	daChunk1, err := codecv1.NewDAChunk(chunk1, 0)
	assert.NoError(t, err)
	chunkBytes1, err := daChunk1.Encode()
	assert.NoError(t, err)

	originalBatch := &Batch{Chunks: []*Chunk{chunk0, chunk1}}
	batch, err := codecv1.NewDABatch(originalBatch)
	assert.NoError(t, err)

	daChunksRawTx, err := codecv1.DecodeDAChunksRawTx([][]byte{chunkBytes0, chunkBytes1})
	assert.NoError(t, err)
	// assert number of chunks
	assert.Equal(t, 2, len(daChunksRawTx))

	// assert block in first chunk
	assert.Equal(t, 2, len(daChunksRawTx[0].Blocks))
	assert.Equal(t, daChunk0.(*daChunkV1).blocks[0], daChunksRawTx[0].Blocks[0])
	assert.Equal(t, daChunk0.(*daChunkV1).blocks[1], daChunksRawTx[0].Blocks[1])

	// assert block in second chunk
	assert.Equal(t, 2, len(daChunksRawTx[1].Blocks))
	daChunksRawTx[1].Blocks[0].(*daBlockV0).baseFee = nil
	assert.Equal(t, daChunk1.(*daChunkV1).blocks[0].(*daBlockV0), daChunksRawTx[1].Blocks[0])
	daChunksRawTx[1].Blocks[1].(*daBlockV0).baseFee = nil
	assert.Equal(t, daChunk1.(*daChunkV1).blocks[1].(*daBlockV0), daChunksRawTx[1].Blocks[1])

	blob := batch.Blob()
	err = codecv1.DecodeTxsFromBlob(blob, daChunksRawTx)
	assert.NoError(t, err)

	// assert transactions in first chunk
	assert.Equal(t, 2, len(daChunksRawTx[0].Transactions))
	// here number of transactions in encoded and decoded chunks may be different, because decodec chunks doesn't contain l1msgs
	assert.Equal(t, 2, len(daChunksRawTx[0].Transactions[0]))
	assert.Equal(t, 1, len(daChunksRawTx[0].Transactions[1]))

	assert.EqualValues(t, daChunk0.(*daChunkV1).transactions[0][0].TxHash, daChunksRawTx[0].Transactions[0][0].Hash().String())
	assert.EqualValues(t, daChunk0.(*daChunkV1).transactions[0][1].TxHash, daChunksRawTx[0].Transactions[0][1].Hash().String())

	// assert transactions in second chunk
	assert.Equal(t, 2, len(daChunksRawTx[1].Transactions))
	// here number of transactions in encoded and decoded chunks may be different, because decodec chunks doesn't contain l1msgs
	assert.Equal(t, 1, len(daChunksRawTx[1].Transactions[0]))
	assert.Equal(t, 0, len(daChunksRawTx[1].Transactions[1]))
}

func TestCodecV1BatchStandardTestCases(t *testing.T) {
	codecv1, err := CodecFromVersion(CodecV1)
	require.NoError(t, err)

	// We then ignore the metadata rows for MaxNumChunksPerBatch chunks.
	nRowsData := maxEffectiveBlobBytes - (codecv1.MaxNumChunksPerBatch()*4 + 2)

	repeat := func(element byte, count int) string {
		result := make([]byte, 0, count)
		for i := 0; i < count; i++ {
			result = append(result, element)
		}
		return "0x" + common.Bytes2Hex(result)
	}

	for _, tc := range []struct {
		chunks                    [][]string
		expectedz                 string
		expectedy                 string
		expectedBlobVersionedHash string
		expectedBatchHash         string
	}{
		// single empty chunk
		{chunks: [][]string{{}}, expectedz: "17c71700d949f82963d3bd6af3994ecc383a3d58007f2f27702758fefa34a925", expectedy: "304817c2a9ec97b4cfdfc7a646f4bd5ac309e967465bb49059d397094e57cd08", expectedBlobVersionedHash: "01a327088bb2b13151449d8313c281d0006d12e8453e863637b746898b6ad5a6", expectedBatchHash: "7d09040c00525af4aff851ba50556d4bc25a28a2bee04d4d02837fdc31da8e5a"},
		// single non-empty chunk
		{chunks: [][]string{{"0x010203"}}, expectedz: "1c1d4bd5153f877d799853080aba243f2c186dd6d6064eaefacfe715c92b6354", expectedy: "24e80ed99526b0d15ba46f7ec682f517576ddae68d5131e5d351f8bae06ea7d3", expectedBlobVersionedHash: "01c57cf97209ce41aaca340099e8eb80984bc54a4f780013cfb9f81bc0641d46", expectedBatchHash: "948fe7a7665c79b975d0f73d47a60150f5f2637fe229f46a0bbacdb282c4359b"},
		// multiple empty chunks
		{chunks: [][]string{{}, {}}, expectedz: "152c9ccfcc2884f9891f7adce2de110cf9f85bfd0e21f0933ae0636390a84d41", expectedy: "5f6f532676e25b49e2eae77513fbeca173a300b434c0a5e24fa554b68e27d582", expectedBlobVersionedHash: "01f2d2978e268e82902df85e773ba3ce0bfbd47067595d876378f062a76c9645", expectedBatchHash: "73a883480442f4ad822d7d8a5660f91ec1b30c2837594175861453ed2aa20c43"},
		// multiple non-empty chunks
		{chunks: [][]string{{"0x010203"}, {"0x070809"}}, expectedz: "62100f5381179ea7db7aa8fdedb0f7fc7b82730b75432d50ab41f80aeebe45a3", expectedy: "5b1f6e7a54907ddc06871853cf1f5d53bf2de0df7b61d0df84bc2c3fb80320cd", expectedBlobVersionedHash: "0103e951d9f758f8c1d073e4dc80a1813c4e0f12454e59d5cf9459baad57a120", expectedBatchHash: "ec0f1219d073a3a06deabf28bbf1dd94c483334a6763a8ae171debfd70c28dba"},
		// empty chunk followed by non-empty chunk
		{chunks: [][]string{{}, {"0x010203"}}, expectedz: "2d94d241c4a2a8d8f02845ca40cfba344f3b42384af2045a75c82e725a184232", expectedy: "302416c177e9e7fe40c3bc4315066c117e27d246b0a33ef68cdda6dd333c485c", expectedBlobVersionedHash: "0197b715c8f9f8c8e295fdd390ee9a629118432f72067398695d9df3c840b7b0", expectedBatchHash: "e84c347c69741d51c26adcffa0e0d23a2621989f5442b6f91a5b2ef409844b4d"},
		// non-empty chunk followed by empty chunk
		{chunks: [][]string{{"0x070809"}, {}}, expectedz: "7227567e3b1dbacb48a32bb85e4e99f73e4bd5620ea8cd4f5ac00a364c86af9c", expectedy: "2eb3dfd28362f35f562f779e749a555d2f1f87ddc716e95f04133d25189a391c", expectedBlobVersionedHash: "01997280b92d3a2b0e6616a57f931e2876c602cf6401617390ad9f6c044c7f9a", expectedBatchHash: "91c1bbb91dda9c5b2a4b11df8433dc62e2690088cb9210a56fe1efa4132fc122"},
		// max number of chunks all empty
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}, expectedz: "1128ac3e22ced6af85be4335e0d03a266946a7cade8047e7fc59d6c8be642321", expectedy: "2d9b16422ce17f328fd00c99349768f0cb0c8648115eb3bd9b7864617ba88059", expectedBlobVersionedHash: "011747bb3b64aaa020e628df02b5dde642b8eefe2acd3bd8768d264b0b230fe2", expectedBatchHash: "7ed0e502c8be58184a6fad9ff83efb2aa4d42632daf00a6527718e041098ece9"},
		// max number of chunks all non-empty
		{chunks: [][]string{{"0x0a"}, {"0x0a0b"}, {"0x0a0b0c"}, {"0x0a0b0c0d"}, {"0x0a0b0c0d0e"}, {"0x0a0b0c0d0e0f"}, {"0x0a0b0c0d0e0f10"}, {"0x0a0b0c0d0e0f1011"}, {"0x0a0b0c0d0e0f101112"}, {"0x0a0b0c0d0e0f10111213"}, {"0x0a0b0c0d0e0f1011121314"}, {"0x0a0b0c0d0e0f101112131415"}, {"0x0a0b0c0d0e0f10111213141516"}, {"0x0a0b0c0d0e0f1011121314151617"}, {"0x0a0b0c0d0e0f101112131415161718"}}, expectedz: "1a4025a3d74e70b511007dd55a2e252478c48054c6383285e8a176f33d99853b", expectedy: "12071ac2571c11220432a27b8be549392892e9baf4c654748ca206def3843940", expectedBlobVersionedHash: "0154c5ae7e60a6cf71c4e1694a4c511d04f9a64e0ebf491fa61227419b9bad15", expectedBatchHash: "eefc56cb4dd1c43415717120fd3d58372e6b052e1533add4f379b58f5acce242"},
		// single chunk blob full
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "72714cc4a0ca75cee2d543b1f958e3d3dd59ac7df0d9d5617d8117b65295a5f2", expectedy: "4ebb690362bcbc42321309c210c99f2ebdb53b3fcf7cf3b17b78f6cfd1203ed3", expectedBlobVersionedHash: "0179bda640290da308c6b4860463db2abb5da3573f188d9db86109644b8888e6", expectedBatchHash: "098cf07b17fd5c684a6e5c47b45c3ead1df8565d785fc508f7e83b1ac43515dc"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "70eb5b4db503e59413238eef451871c5d12f2bb96c8b96ceca012f4ca0114727", expectedy: "568d0aaf280ec83f9c81ed2d80ecbdf199bd72dafb8a350007d37ea82997e455", expectedBlobVersionedHash: "01160d9c7e52ada63878060067f415c0d458143055099d27373842e1fe465542", expectedBatchHash: "c9a7112e924a4799d748b5ac5999fd4c84d6562c2e0cd49c01dbab748de96397"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "03db68ae16ee88489d52db19e6111b25630c5f23ad7cd14530aacf0cd231d476", expectedy: "24527d0b0e93b3dec0060c7b128975a8088b3104d3a297dc807ab43862a77a1a", expectedBlobVersionedHash: "0102b93d4c8ea59ffdd488756a2696702071ac1d90d3140089d737e3babd0213", expectedBatchHash: "8fc9281433f730d9c3efd1fb73f710bdea62f119d61e6b99b34360bda8312d33"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "677670193f73db499cede572bcb55677f0d2f13d690f9a820bd00bf584c3c241", expectedy: "1d85677f172dbdf4ad3094a17deeb1df4d7d2b7f35ecea44aebffa757811a268", expectedBlobVersionedHash: "014e56a635bc97d4fab7b8e33da88453f8050efafe00934210506d3c3b8e63ad", expectedBatchHash: "0109a28c89d11af8bce800c5fd43cbb004e201c17391bc9336f98feef21eb2aa"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "22935042dfe7df771b02c1f5cababfe508869e8f6339dabe25a8a32e37728bb0", expectedy: "48ca66fb5a094401728c3a6a517ffbd72c4d4d9a8c907e2d2f1320812f4d856f", expectedBlobVersionedHash: "017c817651831f769e01728789b6ee29ccd219d4bfa2830c1258b053715592fc", expectedBatchHash: "7a1095c87f9cef674f7049f7b43b0452510dcff44035d8e9bff30adf53afd1f8"},
	} {
		chunks := []*Chunk{}

		for _, c := range tc.chunks {
			block := &Block{Transactions: []*types.TransactionData{}}

			for _, data := range c {
				tx := &types.TransactionData{Type: 0xff, Data: data}
				block.Transactions = append(block.Transactions, tx)
			}

			chunk := &Chunk{Blocks: []*Block{block}}
			chunks = append(chunks, chunk)
		}

		blob, blobVersionedHash, z, err := codecv1.(*DACodecV1).constructBlobPayload(chunks, codecv1.MaxNumChunksPerBatch(), true /* use mock */)
		require.NoError(t, err)
		actualZ := hex.EncodeToString(z[:])
		assert.Equal(t, tc.expectedz, actualZ)
		assert.Equal(t, common.HexToHash(tc.expectedBlobVersionedHash), blobVersionedHash)

		_, y, err := kzg4844.ComputeProof(blob, *z)
		require.NoError(t, err)
		actualY := hex.EncodeToString(y[:])
		assert.Equal(t, tc.expectedy, actualY)

		// Note: this is a dummy dataHash (for each chunk, we use 0xff00..0000)
		dataBytes := make([]byte, 32*len(chunks))
		for i := range chunks {
			copy(dataBytes[32*i:32*i+32], []byte{math.MaxUint8 - uint8(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		}
		dataHash := crypto.Keccak256Hash(dataBytes)

		batch := daBatchV1{
			daBatchV0: daBatchV0{
				version:              CodecV3,
				batchIndex:           6789,
				l1MessagePopped:      101,
				totalL1MessagePopped: 10101,
				dataHash:             dataHash,
				parentBatchHash:      common.BytesToHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
			},
			blobVersionedHash: blobVersionedHash,
			blob:              blob,
			z:                 z,
		}
		assert.Equal(t, common.HexToHash(tc.expectedBatchHash), batch.Hash())
	}
}
