package encoding

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodecV4BlockEncode(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block := &daBlockV0{}
	encoded := hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	daBlock, err := codecv4.NewDABlock(block2, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	daBlock, err = codecv4.NewDABlock(block3, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	daBlock, err = codecv4.NewDABlock(block4, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	daBlock, err = codecv4.NewDABlock(block5, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	daBlock, err = codecv4.NewDABlock(block6, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	daBlock, err = codecv4.NewDABlock(block7, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)

	codecv0, err := CodecFromVersion(CodecV0)
	require.NoError(t, err)

	// sanity check: v0 and v4 block encodings are identical
	for _, trace := range []*Block{block2, block3, block4, block5, block6, block7} {
		blockv0, err := codecv0.NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv0 := hex.EncodeToString(blockv0.Encode())

		blockv4, err := codecv4.NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv4 := hex.EncodeToString(blockv4.Encode())

		assert.Equal(t, encodedv0, encodedv4)
	}
}

func TestCodecV4ChunkEncode(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
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
	daChunk, err := codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)
}

func TestCodecV4ChunkHash(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
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
	daChunk, err := codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x820f25d806ddea0ccdbfa463ee480da5b6ea3906e8a658417fb5417d0f837f5c", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x4620b3900e8454133448b677cbb2054c5dd61d467d7ebf752bfb12cffff90f40", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x059c6451e83012b405c7e1a38818369012a4a1c87d7d699366eac946d0410d73", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x854fc3136f47ce482ec85ee3325adfa16a1a1d60126e1c119eaaf0c3a9e90f8e", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x2aa220ca7bd1368e59e8053eb3831e30854aa2ec8bd3af65cee350c1c0718ba6", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv4.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xb65521bea7daff75838de07951c3c055966750fb5a270fead5e0e727c32455c3", hash.Hex())
}

func TestCodecV4BatchEncode(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	// empty daBatch
	daBatchV3 := &daBatchV3{
		daBatchV0: daBatchV0{
			version: CodecV4,
		},
	}
	encoded := hex.EncodeToString(daBatchV3.Encode())
	assert.Equal(t, "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101e5c897e0f98f6addd6c99bb51ff927cde93851b0d407aae3d7d5de75a31f2900000000000000000000000000000000000000000000000000000000000000000000000063807b2a26451ed31542ed15543973f8bc8c3b6382ba0cba5650a7faf14625377029203c1b6db22aa24613cb68dee10ca50bbbc88fc15b8a6abf9dcf3ad382a2642e480d", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "04000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a601ad8c8eee24cc98ab1ca9c0a4c92bf20f488f06dedbc22f1312bd389df7105000000000000000000000000000000000000000000000000000000000000000000000000063807b2d30702c0ea39553a0601a9c6fc5b27c076ddfc1044001fb0a8ad1fd9016304a61233de2770e0fb9a5578e5f633846ef9fa4c2ab8b80b8f9a30f09be07cda8d725", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f01c6a9a7d06425dbfad42697e4ce5bc8562d7c5ffe1f62d57fcb51240e33af93000000000000000000000000000000000000000000000000000000000000000000000000646b6e1338122423f3cebb92645f9ac93c8ee50edb75ea93a951f278007e721a7b9f995824895b00195499dfe77d201cf3627050d866abb2685f87e10466c4fcaf3a8588", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a000000000000000000000000000000000000000000000000000000000000000000000000646b6ed004e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a000000000000000000000000000000000000000000000000000000000000000000000000646b6ed004e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "04000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a000000000000000000000000000000000000000000000000000000000000000000000000646b6ed004e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", encoded)

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d80113ba3d5c53a035f4b4ec6f8a2ba9ab521bccab9f90e3a713ab5fffc0adec57000000000000000000000000000000000000000000000000000000000000000000000000646b6ed012e49b70b64652e5cab5dfdd1f58958d863de1d7fcb959e09f147a98b0b895171560f81b17ec3a2fe1c8ed2d308ca5bf002d7e3c18db9682a8d0f5379bf213aa", encoded)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e1347670121388d141bd439af8447db5d00bacbfe1587fea6581f795e98588d95ba7f26000000000000000000000000000000000000000000000000000000000000000000000000646b6ed046aedf214a661b6b37b9c325fef4484ff3613a6fb52719609bf02a66bc7ba23b6e9b7bcbe3be0ba95654f16f715bf7e39ef87a84199340423f6487cf56058085", encoded)
}

func TestCodecV4BatchHash(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	// empty daBatch
	daBatchV3 := &daBatchV3{
		daBatchV0: daBatchV0{
			version: CodecV4,
		},
	}
	assert.Equal(t, common.HexToHash("0xdaf0827d02b32d41458aea0d5796dd0072d0a016f9834a2cb1a964d2c6ee135c"), daBatchV3.Hash())

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x53d6da35c9b6f0413b6ebb80f4a8c19b0e3279481ddf602398a54d3b4e5d4f2c"), daBatch.Hash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x08feefdb19215bb0f51f85a3b02a0954ac7da67681e274db49b9102f4c6e0857"), daBatch.Hash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc56c5e51993342232193d1d93124bae30a5b1444eebf49b2dd5f2c5962d4d54d"), daBatch.Hash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x2c32177c8b4c6289d977361c7fd0f1a6ea15add64da2eb8caf0420ac9b35231e"), daBatch.Hash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x909bebbebdbf5ba9c85c6894e839c0b044d2878c457c4942887e3d64469ad342"), daBatch.Hash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x53765a37bbd72655df586b530d79cb4ad0fb814d72ddc95e01e0ede579f45117"), daBatch.Hash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x74ccf9cc265f423cc6e6e53ed294000637a832cdc93c76485855289bebb6764a"), daBatch.Hash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x8d5ee00a80d7dbdc083d0cdedd35c2cb722e5944f9d88f7450c9186f3ef3da44"), daBatch.Hash())
}

func TestCodecV4BatchDataHash(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x9f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed541"), daBatch.DataHash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xd46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a6"), daBatch.DataHash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f"), daBatch.DataHash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4"), daBatch.DataHash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d"), daBatch.DataHash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208"), daBatch.DataHash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xe7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8"), daBatch.DataHash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e134767"), daBatch.DataHash())
}

func TestCodecV4DABatchJSONMarshalUnmarshal(t *testing.T) {
	t.Run("Case 1", func(t *testing.T) {
		expectedJsonStr := `{
			"version": 4,
			"batch_index": 293212,
			"l1_message_popped": 7,
			"total_l1_message_popped": 904750,
			"data_hash": "0xa261ff31f8f78c19f65d14d6394eb911d53a3a3add9a9691b211caa5809be450",
			"blob_versioned_hash": "0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e",
			"parent_batch_hash": "0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee",
			"last_block_timestamp": 1721130505,
			"blob_data_proof": [
				"0x496b144866cffedfd71423639984bf0d9ad4309ff7e35693f1baef3cdaf1471e",
				"0x5eba7d42db109bfa124d1bc4dbcb421944b8aae6eae13a9d55eb460ce402785b"
			]
		}`

		daBatch := daBatchV3{
			daBatchV0: daBatchV0{
				version:              4,
				batchIndex:           293212,
				l1MessagePopped:      7,
				totalL1MessagePopped: 904750,
				dataHash:             common.HexToHash("0xa261ff31f8f78c19f65d14d6394eb911d53a3a3add9a9691b211caa5809be450"),
				parentBatchHash:      common.HexToHash("0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee"),
			},
			blobVersionedHash:  common.HexToHash("0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e"),
			lastBlockTimestamp: 1721130505,
			blobDataProof: [2]common.Hash{
				common.HexToHash("0x496b144866cffedfd71423639984bf0d9ad4309ff7e35693f1baef3cdaf1471e"),
				common.HexToHash("0x5eba7d42db109bfa124d1bc4dbcb421944b8aae6eae13a9d55eb460ce402785b"),
			},
		}

		data, err := json.Marshal(&daBatch)
		require.NoError(t, err, "Failed to marshal daBatch")

		// Compare marshaled JSON
		var expectedJson, actualJson map[string]interface{}
		err = json.Unmarshal([]byte(expectedJsonStr), &expectedJson)
		require.NoError(t, err, "Failed to unmarshal expected JSON string")
		err = json.Unmarshal(data, &actualJson)
		require.NoError(t, err, "Failed to unmarshal actual JSON string")

		assert.Equal(t, expectedJson, actualJson, "Marshaled JSON does not match expected JSON")
	})

	t.Run("Case 2", func(t *testing.T) {
		jsonStr := `{
			"version": 5,
			"batch_index": 123,
			"l1_message_popped": 0,
			"total_l1_message_popped": 0,
			"parent_batch_hash": "0xabacadaeaf000000000000000000000000000000000000000000000000000000",
			"last_block_timestamp": 1720174236,
			"data_hash": "0xa1a518fa8e636dcb736629c296ed10341536c4cf850a3bc0a808d8d66d7f1ee6",
			"blob_versioned_hash": "0x01c61b784ba4cd0fd398717fdc3470729d1a28d70632d520174c9e47614c80e1",
			"blob_data_proof": [
				"0x1ee03153fd007529c214a68934b2cfd51e8586bd142e157564328946a0fc8899",
				"0x118e196a9432c84c53db5a5a7bfbe13ef1ff8ffdba12fbccaf6360110eb71a10"
			]
		}`

		daBatch := daBatchV3{
			daBatchV0: daBatchV0{
				version:              5,
				batchIndex:           123,
				l1MessagePopped:      0,
				totalL1MessagePopped: 0,
				dataHash:             common.HexToHash("0xa1a518fa8e636dcb736629c296ed10341536c4cf850a3bc0a808d8d66d7f1ee6"),
				parentBatchHash:      common.HexToHash("0xabacadaeaf000000000000000000000000000000000000000000000000000000"),
			},
			blobVersionedHash:  common.HexToHash("0x01c61b784ba4cd0fd398717fdc3470729d1a28d70632d520174c9e47614c80e1"),
			lastBlockTimestamp: 1720174236,
			blobDataProof: [2]common.Hash{
				common.HexToHash("0x1ee03153fd007529c214a68934b2cfd51e8586bd142e157564328946a0fc8899"),
				common.HexToHash("0x118e196a9432c84c53db5a5a7bfbe13ef1ff8ffdba12fbccaf6360110eb71a10"),
			},
		}

		data, err := json.Marshal(&daBatch)
		require.NoError(t, err, "Failed to marshal daBatch")

		// Compare marshaled JSON
		var expectedJson, actualJson map[string]interface{}
		err = json.Unmarshal([]byte(jsonStr), &expectedJson)
		require.NoError(t, err, "Failed to unmarshal expected JSON string")
		err = json.Unmarshal(data, &actualJson)
		require.NoError(t, err, "Failed to unmarshal actual JSON string")

		assert.Equal(t, expectedJson, actualJson, "Marshaled JSON does not match expected JSON")
	})

	t.Run("Case 3", func(t *testing.T) {
		jsonStr := `{
			"version": 4,
			"batch_index": 293205,
			"l1_message_popped": 0,
			"total_l1_message_popped": 904737,
			"data_hash": "0x84786e890c015721a37f02a010bd2b84eaf4363cdf04831628a38ddbf497d0bf",
			"blob_versioned_hash": "0x013c7e2c9ee9cd6511e8952e55ce5568832f8be3864de823d4ead5f6dfd382ae",
			"parent_batch_hash": "0x053c0f8b8bea2f7f98dd9dcdc743f1059ca664b2b72a21381b7184dd8aa922e0",
			"last_block_timestamp": 1721129563,
			"blob_data_proof": [
				"0x519fb200d451fea8623ea1bdb15d8138cea68712792a92b9cf1f79dae6df5b54",
				"0x6d50a85330192c8e835cbd6bcdff0f2f23b0b3822e4e0319c92dafd70f0e21da"
			]
		}`

		daBatch := daBatchV3{
			daBatchV0: daBatchV0{
				version:              4,
				batchIndex:           293205,
				l1MessagePopped:      0,
				totalL1MessagePopped: 904737,
				dataHash:             common.HexToHash("0x84786e890c015721a37f02a010bd2b84eaf4363cdf04831628a38ddbf497d0bf"),
				parentBatchHash:      common.HexToHash("0x053c0f8b8bea2f7f98dd9dcdc743f1059ca664b2b72a21381b7184dd8aa922e0"),
			},
			blobVersionedHash:  common.HexToHash("0x013c7e2c9ee9cd6511e8952e55ce5568832f8be3864de823d4ead5f6dfd382ae"),
			lastBlockTimestamp: 1721129563,
			blobDataProof: [2]common.Hash{
				common.HexToHash("0x519fb200d451fea8623ea1bdb15d8138cea68712792a92b9cf1f79dae6df5b54"),
				common.HexToHash("0x6d50a85330192c8e835cbd6bcdff0f2f23b0b3822e4e0319c92dafd70f0e21da"),
			},
		}

		data, err := json.Marshal(&daBatch)
		require.NoError(t, err, "Failed to marshal daBatch")

		// Compare marshaled JSON
		var expectedJson, actualJson map[string]interface{}
		err = json.Unmarshal([]byte(jsonStr), &expectedJson)
		require.NoError(t, err, "Failed to unmarshal expected JSON string")
		err = json.Unmarshal(data, &actualJson)
		require.NoError(t, err, "Failed to unmarshal actual JSON string")

		assert.Equal(t, expectedJson, actualJson, "Marshaled JSON does not match expected JSON")
	})
}

func TestDACodecV4JSONFromBytes(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	daBatch := daBatchV3{
		daBatchV0: daBatchV0{
			version:              4,
			batchIndex:           293212,
			l1MessagePopped:      7,
			totalL1MessagePopped: 904750,
			dataHash:             common.HexToHash("0xa261ff31f8f78c19f65d14d6394eb911d53a3a3add9a9691b211caa5809be450"),
			parentBatchHash:      common.HexToHash("0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee"),
		},
		blobVersionedHash:  common.HexToHash("0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e"),
		lastBlockTimestamp: 1721130505,
		blobDataProof: [2]common.Hash{
			common.HexToHash("0x496b144866cffedfd71423639984bf0d9ad4309ff7e35693f1baef3cdaf1471e"),
			common.HexToHash("0x5eba7d42db109bfa124d1bc4dbcb421944b8aae6eae13a9d55eb460ce402785b"),
		},
	}

	outputJSON, err := codecv4.JSONFromBytes(daBatch.Encode())
	require.NoError(t, err, "JSONFromBytes failed")

	var outputMap map[string]interface{}
	err = json.Unmarshal(outputJSON, &outputMap)
	require.NoError(t, err, "Failed to unmarshal output JSON")

	expectedFields := map[string]interface{}{
		"version":                 float64(daBatch.version),
		"batch_index":             float64(daBatch.batchIndex),
		"l1_message_popped":       float64(daBatch.l1MessagePopped),
		"total_l1_message_popped": float64(daBatch.totalL1MessagePopped),
		"data_hash":               daBatch.dataHash.Hex(),
		"blob_versioned_hash":     daBatch.blobVersionedHash.Hex(),
		"parent_batch_hash":       daBatch.parentBatchHash.Hex(),
		"last_block_timestamp":    float64(daBatch.lastBlockTimestamp),
		"blob_data_proof": []interface{}{
			daBatch.blobDataProof[0].Hex(),
			daBatch.blobDataProof[1].Hex(),
		},
	}

	assert.Len(t, outputMap, len(expectedFields), "Unexpected number of fields in output")
	for key, expectedValue := range expectedFields {
		assert.Equal(t, expectedValue, outputMap[key], fmt.Sprintf("Mismatch in field %s", key))
	}
}

func TestCodecV4CalldataSizeEstimation(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2CalldataSize, err := codecv4.EstimateChunkL1CommitCalldataSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk2CalldataSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2CalldataSize, err := codecv4.EstimateBatchL1CommitCalldataSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch2CalldataSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3CalldataSize, err := codecv4.EstimateChunkL1CommitCalldataSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk3CalldataSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3CalldataSize, err := codecv4.EstimateBatchL1CommitCalldataSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch3CalldataSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4CalldataSize, err := codecv4.EstimateChunkL1CommitCalldataSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk4CalldataSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4CalldataSize, err := codecv4.EstimateBatchL1CommitCalldataSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch4CalldataSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5CalldataSize, err := codecv4.EstimateChunkL1CommitCalldataSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(120), chunk5CalldataSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6CalldataSize, err := codecv4.EstimateChunkL1CommitCalldataSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk6CalldataSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5CalldataSize, err := codecv4.EstimateBatchL1CommitCalldataSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(180), batch5CalldataSize)
}

func TestCodecV4CommitGasEstimation(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2Gas, err := codecv4.EstimateChunkL1CommitGas(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(51124), chunk2Gas)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2Gas, err := codecv4.EstimateBatchL1CommitGas(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(207649), batch2Gas)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3Gas, err := codecv4.EstimateChunkL1CommitGas(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(51124), chunk3Gas)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3Gas, err := codecv4.EstimateBatchL1CommitGas(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(207649), batch3Gas)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4Gas, err := codecv4.EstimateChunkL1CommitGas(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(53745), chunk4Gas)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4Gas, err := codecv4.EstimateBatchL1CommitGas(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(210302), batch4Gas)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5Gas, err := codecv4.EstimateChunkL1CommitGas(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(52202), chunk5Gas)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6Gas, err := codecv4.EstimateChunkL1CommitGas(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(53745), chunk6Gas)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5Gas, err := codecv4.EstimateBatchL1CommitGas(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(213087), batch5Gas)
}

func TestCodecV4BatchSizeAndBlobSizeEstimation(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2BatchBytesSize, chunk2BlobSize, err := codecv4.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), chunk2BatchBytesSize)
	assert.Equal(t, uint64(238), chunk2BlobSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2BatchBytesSize, batch2BlobSize, err := codecv4.EstimateBatchL1CommitBatchSizeAndBlobSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), batch2BatchBytesSize)
	assert.Equal(t, uint64(238), batch2BlobSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3BatchBytesSize, chunk3BlobSize, err := codecv4.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), chunk3BatchBytesSize)
	assert.Equal(t, uint64(2934), chunk3BlobSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3BatchBytesSize, batch3BlobSize, err := codecv4.EstimateBatchL1CommitBatchSizeAndBlobSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), batch3BatchBytesSize)
	assert.Equal(t, uint64(2934), batch3BlobSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4BatchBytesSize, chunk4BlobSize, err := codecv4.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk4BatchBytesSize)
	assert.Equal(t, uint64(55), chunk4BlobSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	blob4BatchBytesSize, batch4BlobSize, err := codecv4.EstimateBatchL1CommitBatchSizeAndBlobSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), blob4BatchBytesSize)
	assert.Equal(t, uint64(55), batch4BlobSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5BatchBytesSize, chunk5BlobSize, err := codecv4.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6093), chunk5BatchBytesSize)
	assert.Equal(t, uint64(3150), chunk5BlobSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6BatchBytesSize, chunk6BlobSize, err := codecv4.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk6BatchBytesSize)
	assert.Equal(t, uint64(55), chunk6BlobSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5BatchBytesSize, batch5BlobSize, err := codecv4.EstimateBatchL1CommitBatchSizeAndBlobSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6125), batch5BatchBytesSize)
	assert.Equal(t, uint64(3187), batch5BlobSize)
}

func TestCodecV4BatchL1MessagePopped(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV3).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV3).totalL1MessagePopped)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV3).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV3).totalL1MessagePopped)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV3).l1MessagePopped)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV3).totalL1MessagePopped)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV3).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV3).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 37
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), daBatch.(*daBatchV3).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV3).totalL1MessagePopped)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), daBatch.(*daBatchV3).l1MessagePopped) // skip 7, include 3
	assert.Equal(t, uint64(10), daBatch.(*daBatchV3).totalL1MessagePopped)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(257), daBatch.(*daBatchV3).l1MessagePopped) // skip 255, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV3).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 1
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(256), daBatch.(*daBatchV3).l1MessagePopped) // skip 254, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV3).totalL1MessagePopped)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}} // queue index 10
	chunk9 := &Chunk{Blocks: []*Block{block5}}                 // queue index 37-41
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV3).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV3).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 10
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(32), daBatch.(*daBatchV3).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV3).totalL1MessagePopped)
}

func TestCodecV4BlobEncodingAndHashing(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	batch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded := strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "0001609c00fd0600240d0001000000e600f87180843b9aec2e8307a12094c0c400c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808300019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a0041e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfa00ec288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf00039985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f7731600a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed0032f1030060b26d07d8b028b005", encoded)
	assert.Equal(t, common.HexToHash("0x01e5c897e0f98f6addd6c99bb51ff927cde93851b0d407aae3d7d5de75a31f29"), batch.(*daBatchV3).blobVersionedHash)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "000160e7159d580094830001000016310002f9162d82cf5502843b9b0a1783110097e28080b915d260806040523480156200001157600080fd5b5060405162000014b2380380833981810160405260a0811037815160208301516040808501800051915193959294830192918464018211639083019060208201858179825181001182820188101794825250918201929091019080838360005b83c357818101005183820152602001620000a9565b50505050905090810190601f16f1578082000380516001836020036101000a031916819150805160405193929190011501002b01460175015b01a39081015185519093508592508491620001c891600391008501906200026b565b508051620001de90600490602084506005805461ff00001960ff1990911660121716905550600680546001600160a01b0380881619920083161790925560078054928716929091169190911790556200023081620002005562010000600160b01b03191633021790555062000307915050565b60ff19001660ff929092565b828160011615610100020316600290049060005260206000002090601f016020900481019282601f10620002ae5780518380011785de010060010185558215620002de579182015b8202de5782518255916020019190600001c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000002f1565b61119b80620003176000396000f3fe61001004361061010b576000003560e01c80635c975abb116100a257806395d89b411161007114610301570080639dc29fac14610309578063a457c2d714610335578063a9059cbb1461030061578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114610002a55780638456cb59146102cb5780638e50817a146102d3313ce56711610000de571461021d578063395093511461023b5780633f4ba83a146102675780630040c10f191461027106fdde0314610110578063095ea7b31461018d5780631800160ddd146101cd57806323b872e7575b6101186103bb565b6040805160208000825283518183015283519192839290830161015261013a61017f9250508091000390f35b6101b9600480360360408110156101a381351690602001356104510091151582525190819003602001d561046e60fd81169160208101359091169000604074565b6102256104fb60ff90921640025105046f610552565b005b6102006f028705a956610654d520bb3516610662067d56e90135166106d21861075700031f07b856034b085f77c7d5a308db565b6003805420601f600260001961010000600188161502019095169490940493840181900481028201810190925282008152606093909290918301828280156104475780601f1061041c57610100800083540402835291610447565b825b8154815260200180831161042a5782900300601f16820191565b600061046561045e610906565b848461090a565b506001009202548184f6565b6104f18461048d6104ec8560405180606080602861108500602891398a166000908152600160205260408120906104cb81019190915260004001600020549190610b51565b935460ff160511016000610522908116825200602080830193909352604091820120918c168152925290205490610be8565b00600716331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b001b1bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090000460ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606004606508282610ced909052604006ca0ddd900407260c6b6f6e6c792046616300746f727960a0079283918216179091559390921660041561080808550e6508006c2511176025006108968dd491824080832093909416825233831661094f5700040180806020018281038252602401806110f36024913960400191fd821661000994223d60228084166000819487168084529482529182902085905581518500815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b20000ac8c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a008b838383610f61565b610ac881265f60268685808220939093559084168152002054610af7908220409490945580905191937fddf252ad1be2c89b69c2b06800fc378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484111500610be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53006166654d6174683a206164646974696f6e206f766572666c6f7700610c9c140073621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537b00d38aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e742074006f20746865207a65726f72657373610d546000600254610d61025590205461000d8780838393519293910e2d6101001790557f62e78cea01bee320cd4e42020070b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad602161000eb68260000ef3221b85839020550f199082610fb540805182600091851691009120565b610f6cb07415610fb02a113c602a00610c428383401e7375627472006163815250fe7472616e736665726275726e20616d6f756e742065786365650064732062616c616e6365617070726f7665616c6c6f7766726f6d646563726500617365642062656c6f775061757361626c653a20746f6b656e7768696c652000706175736564a2646970667358221220e96342bec8f6c2bf72815a3999897300b64c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a7700d9fa7ef466951b2f01f724bca3a5820b63a0e012095745544820636f696e0400c001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f055003c633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda5200095d44b8a9af7813ca8c134a9149a111111110549d2740105c410e61ca4d60300126013290b6398528818e2c8484081888c4890142465a631e63178f994004800f46ba77adb9be01e898bbbfbc0afba2b64ed71162098740e35ec699633c6a80049670da2d948458ecd9f2e5dc5c5ac4afe3d62cf457cd3507b2eae71e064fa00b388531f9c708fd40558dfc698511c4a68234d058c4972da28f0201c4ee55000b5e36f0bb42e46bb556d6197be7ea27a3a853e5da024de5ea930350219b163008aa1dcd41f8222f5d647291e05238c248aa4e028278ad4a9a720f5c16f637100664c4cc255e402cdf64c88e9231dd28a07b8f0ddf1dd7b388875a13dc6d44700c0318bca02c54cdfa3621635af1ff932928dfde06038ac9729c301f9f3a3a300958d502ba9e137cc24c14cb4102cf6ba6708b9c812c3ba59a3cbcc5d2aafa800b597b49fbeb704a22b6137ae9a13b600ad73748768b42756ba338f9854164b001b3f3e23255e4db853a2d3276f061093a37810212ba36db205219fab403242008009178588ad21f754085dd807b09af69e6f06bccbcef8ade3b1f0eb15a07700b85b024ecef4087f261a0d4033355c1e544bd0b0c100276008c420d6d30bc800bea3ba741063e8b48cf152d3695c0904d477318d4ad46477cdf96244333647009fbd86fd52d4e2a1d23eeddc52463d524b44644abdcd097025bcf9cc636fc1000392cb15b81d7ea667f3ba711624bbf04e992871a6ea4f9d367ba6d4614217006fcdf03e4e19549d2eea45ca804421f6bc33933aab6d478b291bf3619fe15b00c9975409d8f3677a87d1b1f7acdb3071b752f3d95c9363ac9c83752f223e4500e579308f554787b4d1f74e389823923f5d268be545466a2dd449963ad2540700bd3a18601410b91ca081537f67ea8d527a49adf256f2363346ea35a2fe276800a9091a184f59680df81982c6087efc651f54693a7870aa7c13dcf054c3953600c5de8a2dd66955567ff1730dac8533de482aed706ed3417823dd65d058b98800998d54917fd1f70735f7a6a8b1a053c08aac96fb04", encoded)
	assert.Equal(t, common.HexToHash("0x01ad8c8eee24cc98ab1ca9c0a4c92bf20f488f06dedbc22f1312bd389df71050"), batch.(*daBatchV3).blobVersionedHash)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "000120d67d0100740200010000002000df0b80825dc0941a258d17bf244c4df0002d40343a7626a9d321e105808080808001002c0a1801", encoded)
	assert.Equal(t, common.HexToHash("0x01c6a9a7d06425dbfad42697e4ce5bc8562d7c5ffe1f62d57fcb51240e33af93"), batch.(*daBatchV3).blobVersionedHash)

	// this batch only contains L1 txs
	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "00000001", encoded)
	assert.Equal(t, common.HexToHash("0x016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a"), batch.(*daBatchV3).blobVersionedHash)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "00000001", encoded)
	assert.Equal(t, common.HexToHash("0x016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a"), batch.(*daBatchV3).blobVersionedHash)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "00000001", encoded)
	assert.Equal(t, common.HexToHash("0x016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a"), batch.(*daBatchV3).blobVersionedHash)

	// 45 chunks
	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "00016024281d0700140d002d000000e6f87180843b9aec2e8307a12094c0c4c800baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808301009ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a4100e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec00288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03900985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a0005a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed3200f1040041e1491b3e82c9b61d60d39a727", encoded)
	assert.Equal(t, common.HexToHash("0x0128a4e122c179a7c34ab1f22ceadf6fa66d2bb0d229933fe1ed061dd8b1fb5f"), batch.(*daBatchV3).blobVersionedHash)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	batch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV3).blob[:]), "0")
	assert.Equal(t, "000160ed16256000449200020000173700f87180843b9aec2e8307a12094c0c400c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808300019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a0041e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfa00ec288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf00039985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f7731600a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed0032f102f9162d82cf5502843b9b0a17831197e28080b915d26080604052348000156200001157600080fd5b50604051620014b238038083398181016040526000a0811037815160208301516040808501805191519395929483019291846401008211639083019060208201858179825181118282018810179482525091820100929091019080838360005b83c3578181015183820152602001620000a9565b0050505050905090810190601f16f15780820380516001836020036101000a030019168191508051604051939291900115012b01460175015b01a3908101518500519093508592508491620001c8916003918501906200026b565b50805162000001de90600490602084506005805461ff001960ff199091166012171690555000600680546001600160a01b03808816199283161790925560078054928716920090911691909117905562000230816200025562010000600160b01b0319163300021790555062000307915050565b60ff191660ff929092565b828160011615006101000203166002900490600052602060002090601f01602090048101928200601f10620002ae5780518380011785de0160010185558215620002de57918200015b8202de57825182559160200191906001c1565b50620002ec9291f0565b005090565b5b8002ec5760008155600101620002f1565b61119b8062000317600000396000f3fe61001004361061010b5760003560e01c80635c975abb11610000a257806395d89b4111610071146103015780639dc29fac14610309578063a40057c2d714610335578063a9059cbb14610361578063dd62ed3e1461038d576100010b565b1461029d57806370a08231146102a55780638456cb59146102cb570080638e50817a146102d3313ce567116100de571461021d57806339509351140061023b5780633f4ba83a1461026757806340c10f191461027106fdde031461000110578063095ea7b31461018d57806318160ddd146101cd57806323b872e700575b6101186103bb565b6040805160208082528351818301528351919283920090830161015261013a61017f92505080910390f35b6101b960048036036040008110156101a3813516906020013561045191151582525190819003602001d50061046e60fd811691602081013590911690604074565b6102256104fb60ff9000921640025105046f610552565b005b61026f028705a956610654d520bb351600610662067d56e90135166106d218610757031f07b856034b085f77c7d5a30800db565b6003805420601f600260001961010060018816150201909516949094000493840181900481028201810190925282815260609390929091830182828000156104475780601f1061041c576101008083540402835291610447565b825b008154815260200180831161042a57829003601f16820191565b60006104656100045e610906565b848461090a565b5060019202548184f6565b6104f1846104008d6104ec85604051806060806028611085602891398a16600090815260016000205260408120906104cb810191909152604001600020549190610b51565b93005460ff160511016000610522908116825260208083019390935260409182010020918c168152925290205490610be8565b600716331461059f5762461bcd6000e51b60040b60248201526a1b9bdd08185b1b1bddd95960aa1b60448201529000640190fd5b6105a7610c49565b610100900460ff16156105f9106f14185d5c00d8589b194e881c185d5cd95960826006064606508282610ced90905260400600ca0ddd900407260c6b6f6e6c7920466163746f727960a007928391821617900091559390921660041561080808550e65086c2511176025006108968dd49182004080832093909416825233831661094f5704018080602001828103825260240001806110f36024913960400191fd8216610994223d60228084166000819487001680845294825291829020859055815185815291517f8c5be1e5ebec7d5bd1004f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92592819003a350831600610a3b25ce8216610a80230ff86023610a8b838383610f61565b610ac88126005f602686858082209390935590841681522054610af790822040949094558000905191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f5005a4df523b3ef9291829003008184841115610be08381815191508051900ba5000b8d0bd2fd900300828201610c421b7f536166654d6174683a20616464697400696f6e206f766572666c6f7700610c9c1473621690557f5db9ee0a495bf2e600ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa610cd0a1821661000d481f7f45524332303a206d696e7420746f20746865207a65726f7265737300610d546000600254610d610255902054610d8780838393519293910e2d610100001790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdb00fc544b05a2588216610eaa6021ad6021610eb68260000ef3221b8583902055000f199082610fb5408051826000918516919120565b610f6cb07415610fb02a00113c602a00610c428383401e73756274726163815250fe7472616e73666572006275726e20616d6f756e7420657863656564732062616c616e636561707072006f7665616c6c6f7766726f6d6465637265617365642062656c6f77506175730061626c653a20746f6b656e7768696c6520706175736564a264697066735822001220e96342bec8f6c2bf72815a39998973b64c3bed57770f402e9a7b7eeda000265d4c64736f6c634300060c00331c5a77d9fa7ef466951b2f01f724bca3a500820b63a0e012095745544820636f696e04c001a0235c1a8d40e8c34789039700f1a92e6eadbd6422cf7c210e3e1737f0553c633172a02f7c0384ddd0697044006e74229cd96216da62196dc62395bda52095d44b8a9af7df0b80825dc0941a00258d17bf244c4df02d40343a7626a9d321e1058080808080813ea8c134a914009a111111110549d2740105c410e61ca4d603126013290b6398528818e2c848004081888c4890142465a631e63178f9940048f46ba77adb9be01e898bbbfb8000ccba2b64ed71162098740e35ec699633c6a849670da2d948458ecd9f2e5dc500c5ac4afe3d62cf457cd3507b2eae71e064fab388531f9c708fd40558dfc69800511c4a68234d058c4972da28f0201c4ee550b5e36f0bb42e46bb556d6197be007ea27a3a853e5da024de5ea930350219b1638aa1dcd41f8222f5d647291e0500238c248aa4e028278ad4a9a720f5c16f6371664c4cc255e402cdf64c88e923001dd28a07b8f0ddf1dd7b388875a13dc6d447c0318bca02c54cdfa3621635af001ff932928dfde06038ac9729c301f9f3a3a3958d502ba9e137cc24c14cb410002cf6ba6708b9c812c3ba59a3cbcc5d2aafa8b597b49fbeb704a22b6137ae9a0013b600ad73748768b42756ba338f9854164b1b3f3e23255e4db853a2d3276f00061093a37810212ba36db205219fab4032428009178588ad21f754085dd80700b09af69e6f06bccbcef8ade3b1f0eb15a077b85b024ecef4087f261a0d403300355c1e544bd0b0c100276008c420d6d30bc8bea3ba741063e8b48cf152d369005c0904d477318d4ad46477cdf962443336479fbd86fd52d4e2a1d23eeddc5200463d524b44644abdcd097025bcf9cc636fc10392cb15b81d7ea667f3ba71160024bbf04e992871a6ea4f9d367ba6d46142176fcdf03e4e19549d2eea45ca80004421f6bc33933aab6d478b291bf3619fe15bc9975409d8f3677a87d1b1f7ac00db3071b752f3d95c9363ac9c83752f223e45e579308f554787b4d1f74e38980023923f5d268be545466a2dd449963ad25407bd3a18601410b91ca081537f6700ea8d527a49adf256f2363346ea35a2fe2768a9091a184f59680df81982c608007efc651f54693a7870aa7c13dcf054c39536c5de8a2dd66955567ff1730dac008533de482aed706ed3417823dd65d058b988998d54917fe9bb80f5ee4d5c63006da70ee60a586fdb282babf53e01", encoded)
	assert.Equal(t, common.HexToHash("0x0121388d141bd439af8447db5d00bacbfe1587fea6581f795e98588d95ba7f26"), batch.(*daBatchV3).blobVersionedHash)
}

func TestCodecV4BatchBlobDataProofForPointEvaluation(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err := daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "26451ed31542ed15543973f8bc8c3b6382ba0cba5650a7faf14625377029203c1b6db22aa24613cb68dee10ca50bbbc88fc15b8a6abf9dcf3ad382a2642e480db5eb389fe4a7fcba73975e3ebc5f1f7f040022a51e20a94a1a67471fc0f4dfb23eaeff14ce3fd2d0928f644b6d6b11d5ac5e0f3f19d94f4e12b775d39c7d970363fe6ccd9b23c006b8dc25512cb7b9d1d85521c4893983e52f7e9844a7dc8eca", hex.EncodeToString(verifyData))

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30702c0ea39553a0601a9c6fc5b27c076ddfc1044001fb0a8ad1fd9016304a61233de2770e0fb9a5578e5f633846ef9fa4c2ab8b80b8f9a30f09be07cda8d72598f7a0eb89cf859212035316e58dc2d291a73b84a36d61b94166ece830f7a6316bb378e098602ffc0e66adc1e33c8608a3b39da9b1c0565a19cbf3ab6415c7bb3ddfeb6d63d204c4670f5777fdee9ffa5f6aec4085924f4af2fe27142eec0cd2", hex.EncodeToString(verifyData))

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "38122423f3cebb92645f9ac93c8ee50edb75ea93a951f278007e721a7b9f995824895b00195499dfe77d201cf3627050d866abb2685f87e10466c4fcaf3a8588a695aaff41dcefb301a7b597c201940b3c64439e4b74c23b7280def1d1b160e4121129f7f0015f3e880b9b7594de04a5a7445c20b31d8786754ed6f9fbafe69b24d738055c5cad62a502e9b7d717aa45636022a24c0a83bbf411157054957638", hex.EncodeToString(verifyData))

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "04e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a92139250d65777a7748934f3e2992f17a66affd58b341854cf7a0837d976903f412189ad04ea1003bdc602ebf33d3af43e23a9c69bb3a38a5e633154ada88e361cc633194fc01bab0d496c1541654f112f5ed258d3bde8ca0ca38b69c26d8813c268", hex.EncodeToString(verifyData))

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "04e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a92139250d65777a7748934f3e2992f17a66affd58b341854cf7a0837d976903f412189ad04ea1003bdc602ebf33d3af43e23a9c69bb3a38a5e633154ada88e361cc633194fc01bab0d496c1541654f112f5ed258d3bde8ca0ca38b69c26d8813c268", hex.EncodeToString(verifyData))

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "04e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a92139250d65777a7748934f3e2992f17a66affd58b341854cf7a0837d976903f412189ad04ea1003bdc602ebf33d3af43e23a9c69bb3a38a5e633154ada88e361cc633194fc01bab0d496c1541654f112f5ed258d3bde8ca0ca38b69c26d8813c268", hex.EncodeToString(verifyData))

	// 45 chunks
	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "237ce1b89c4534d34df2f0102af375a93128e88d5f762d3af6d109b63986fef525261e41884dc3b9998b8929b38a7ed6a0b5c91e98f7bc280971a0ef265680cc902969e14a0716e5ff34fc4cdabf7e0319f8456301d1e5643be4ab4f86fe4dbcfa26594ffbf3a496ab07db4eb2471eb5a669bac77d6ff53dd202957a0d5b27f8a4fc94de92e01715a6c9d7cb54f1d25ccc13a7096b62592edb5c0f4ff6d45545", hex.EncodeToString(verifyData))

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "46aedf214a661b6b37b9c325fef4484ff3613a6fb52719609bf02a66bc7ba23b6e9b7bcbe3be0ba95654f16f715bf7e39ef87a84199340423f6487cf56058085a21962439624643e7ad898db06e9bf9432d937f3ae8cf465f1e92501497314abec74c632b4cde93d73acd1235755a4de8ef007cb7cb577864c81c4d5a80bf68e1b2bed33f54fa82b4f197b6614f69c4cfbbf2b63df630801d8abd8020a52b845", hex.EncodeToString(verifyData))
}

func TestCodecV4DecodeDAChunksRawTx(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	block0 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	block1 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk0 := &Chunk{Blocks: []*Block{block0, block1}}
	daChunk0, err := codecv4.NewDAChunk(chunk0, 0)
	assert.NoError(t, err)
	chunkBytes0, err := daChunk0.Encode()
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	block3 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk1 := &Chunk{Blocks: []*Block{block2, block3}}
	daChunk1, err := codecv4.NewDAChunk(chunk1, 0)
	assert.NoError(t, err)
	chunkBytes1, err := daChunk1.Encode()
	assert.NoError(t, err)

	originalBatch := &Batch{Chunks: []*Chunk{chunk0, chunk1}}
	batch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)

	daChunksRawTx1, err := codecv4.DecodeDAChunksRawTx([][]byte{chunkBytes0, chunkBytes1})
	assert.NoError(t, err)
	// assert number of chunks
	assert.Equal(t, 2, len(daChunksRawTx1))

	// assert block in first chunk
	assert.Equal(t, 2, len(daChunksRawTx1[0].Blocks))
	assert.Equal(t, daChunk0.(*daChunkV1).blocks[0], daChunksRawTx1[0].Blocks[0])
	assert.Equal(t, daChunk0.(*daChunkV1).blocks[1], daChunksRawTx1[0].Blocks[1])

	// assert block in second chunk
	assert.Equal(t, 2, len(daChunksRawTx1[1].Blocks))
	daChunksRawTx1[1].Blocks[0].(*daBlockV0).baseFee = nil
	assert.Equal(t, daChunk1.(*daChunkV1).blocks[0].(*daBlockV0), daChunksRawTx1[1].Blocks[0])
	daChunksRawTx1[1].Blocks[1].(*daBlockV0).baseFee = nil
	assert.Equal(t, daChunk1.(*daChunkV1).blocks[1].(*daBlockV0), daChunksRawTx1[1].Blocks[1])

	blob := batch.Blob()
	err = codecv4.DecodeTxsFromBlob(blob, daChunksRawTx1)
	assert.NoError(t, err)

	// assert transactions in first chunk
	assert.Equal(t, 2, len(daChunksRawTx1[0].Transactions))
	// here number of transactions in encoded and decoded chunks may be different, because decodec chunks doesn't contain l1msgs
	assert.Equal(t, 2, len(daChunksRawTx1[0].Transactions[0]))
	assert.Equal(t, 1, len(daChunksRawTx1[0].Transactions[1]))

	assert.EqualValues(t, daChunk0.(*daChunkV1).transactions[0][0].TxHash, daChunksRawTx1[0].Transactions[0][0].Hash().String())
	assert.EqualValues(t, daChunk0.(*daChunkV1).transactions[0][1].TxHash, daChunksRawTx1[0].Transactions[0][1].Hash().String())

	// assert transactions in second chunk
	assert.Equal(t, 2, len(daChunksRawTx1[1].Transactions))
	// here number of transactions in encoded and decoded chunks may be different, because decodec chunks doesn't contain l1msgs
	assert.Equal(t, 1, len(daChunksRawTx1[1].Transactions[0]))
	assert.Equal(t, 0, len(daChunksRawTx1[1].Transactions[1]))

	// Uncompressed case
	block4 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk2 := &Chunk{Blocks: []*Block{block4}}
	daChunk2, err := codecv4.NewDAChunk(chunk2, 0)
	assert.NoError(t, err)
	chunkBytes2, err := daChunk2.Encode()
	assert.NoError(t, err)

	daChunksRawTx2, err := codecv4.DecodeDAChunksRawTx([][]byte{chunkBytes2})
	assert.NoError(t, err)

	// assert number of chunks
	assert.Equal(t, 1, len(daChunksRawTx2))

	// assert block in uncompressed chunk
	assert.Equal(t, 1, len(daChunksRawTx2[0].Blocks))
	assert.Equal(t, daChunk2.(*daChunkV1).blocks[0].Encode(), daChunksRawTx2[0].Blocks[0].Encode())

	daBatchUncompressed, err := codecv4.NewDABatch(&Batch{Chunks: []*Chunk{chunk2}})
	assert.NoError(t, err)
	blobUncompressed := daBatchUncompressed.Blob()
	err = codecv4.DecodeTxsFromBlob(blobUncompressed, daChunksRawTx2)
	assert.NoError(t, err)

	// assert transactions in first chunk
	assert.Equal(t, 1, len(daChunksRawTx2[0].Transactions))
	assert.Equal(t, 0, len(daChunksRawTx2[0].Transactions[0]))
}

func TestCodecV4BatchStandardTestCasesEnableCompression(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	// Taking into consideration compression, we allow up to 5x of max blob bytes minus 1 byte for the compression flag.
	// We then ignore the metadata rows for MaxNumChunksPerBatch chunks.
	nRowsData := 5*(maxEffectiveBlobBytes-1) - (codecv4.MaxNumChunksPerBatch()*4 + 2)

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
		{chunks: [][]string{{}}, expectedz: "1517a7f04a9f2517aaad8440792de202bd1fef70a861e12134c882ccf0c5a537", expectedy: "1ff0c5ea938308566ab022bc30d0136792084dc9adca93612ec925411915d4a9", expectedBlobVersionedHash: "015f16731c3e7864a08edae95f11db8c96e39a487427d7e58b691745d87f8a21", expectedBatchHash: "c3cfeead404a6de1ec5feaa29b6c1c1a5e6a40671c5d5e9cf1dd86fdf5a2e44a"},
		// single non-empty chunk
		{chunks: [][]string{{"0x010203"}}, expectedz: "2cbd5fb174611060e72a2afcc385cea273b0f5ea8656f04f3661d757a6b00ff9", expectedy: "68d653e973d32fc5b79763d1b7de1699f37e2527830331b1a02f39d58d7070a9", expectedBlobVersionedHash: "019de38b4472451c5e8891dbb01bc2e834d660198cb9878e6b94fb55e4aaf92b", expectedBatchHash: "41e1c4a5220feb7fed5ba9e3980d138b8d5b4b06b8a46a87d796dbf5ed9265f5"},
		// multiple empty chunks
		{chunks: [][]string{{}, {}}, expectedz: "0f9270fd0f21c1eef46334614c586759a2fb71ae46fef50560e92ef7ec926ccc", expectedy: "028f18fc74210d214d3e78a5f92f5c68a9d4dcc633e6e7ffb4144651a39b9dce", expectedBlobVersionedHash: "014a46e5be597971d313e300a052dc406b9f06fad394e1ba115df7da9ca5746d", expectedBatchHash: "94cac32609ae6c3d99dacf5af3650a7748b4dcf8c9779353b932a75e85bc2632"},
		// multiple non-empty chunks
		{chunks: [][]string{{"0x010203"}, {"0x070809"}}, expectedz: "3a199bd64627e67c320add8a5932870535c667236eda365c989f0b73176bb000", expectedy: "221d60db4912e9067df77ee3d71587ea1023ec0238c23044a3325f909fd5ceb3", expectedBlobVersionedHash: "0145df6dbf8070bb3137156fe4540c11330e84487fcac24239442859d95e925c", expectedBatchHash: "d2332749a82a3b94766493ee3826074b8af74efc98367d14fd82e1056e2abf88"},
		// empty chunk followed by non-empty chunk
		{chunks: [][]string{{}, {"0x010203"}}, expectedz: "0a421d448784eb111c2ae9a8031a7cf79e4638b300c48d0c7ff38322e25268fc", expectedy: "48ad5516b1370ac6be17a1d3220e286c9522366ec36fc66a584bbe1ee904eaf1", expectedBlobVersionedHash: "019e5c4c0bfa68324657a0d2e49075eeee2e7c928811bc9c8b2c03888d9d3a5d", expectedBatchHash: "5eac258323d1a4d166d2d116b330262440f46f1ecf07b247cc792bca4a905761"},
		// non-empty chunk followed by empty chunk
		{chunks: [][]string{{"0x070809"}, {}}, expectedz: "6aa26c5d595fa1b72c4e1aa4f06b35788060a7504137c7dd6896486819445230", expectedy: "72c082827841ab84576b49cd63bd06af07cb090626ea3e91a8e77de29b3e61dc", expectedBlobVersionedHash: "0166c93797bf7d4e5701d36bfc8bcea5270c1c4ff18d1aaa248125c87746cf3d", expectedBatchHash: "03e0bdf053fa21d37bf55ac27e7774298b95465123c353e30761e51965269a10"},
		// max number of chunks all empty
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}, expectedz: "4a04cb1860de2c0d03a78520da62a447ef2af92e36dc0b1806db501d7cf63469", expectedy: "17ca30439aed3d9a96f4336d2a416da04a0803667922c7b0765557bb0162493f", expectedBlobVersionedHash: "014b8172c9e2ef89ac8d2ff0c9991baafff3602459250f5870721ac4f05dca09", expectedBatchHash: "216add0492703b12b841ebf6d217a41d1907dd4acd54d07a870472d31d4fde0d"},
		// max number of chunks all non-empty
		{chunks: [][]string{
			{"0x0a"},
			{"0x0a0b"},
			{"0x0a0b0c"},
			{"0x0a0b0c0d"},
			{"0x0a0b0c0d0e"},
			{"0x0a0b0c0d0e0f"},
			{"0x0a0b0c0d0e0f10"},
			{"0x0a0b0c0d0e0f1011"},
			{"0x0a0b0c0d0e0f101112"},
			{"0x0a0b0c0d0e0f10111213"},
			{"0x0a0b0c0d0e0f1011121314"},
			{"0x0a0b0c0d0e0f101112131415"},
			{"0x0a0b0c0d0e0f10111213141516"},
			{"0x0a0b0c0d0e0f1011121314151617"},
			{"0x0a0b0c0d0e0f101112131415161718"},
			{"0x0a0b0c0d0e0f10111213141516171819"},
			{"0x0a0b0c0d0e0f101112131415161718191a"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"},
		}, expectedz: "53eafb50809b3473cb4f8764f7e5d598af9eaaddc45a5a6da7cddac3380e39bb", expectedy: "40751ed98861f5c2058b4062b275f94a3d505a3221f6abe8dbe1074a4f10d0f4", expectedBlobVersionedHash: "01b78b07dbe03b960cd73ea45088b231a50ce88408fa938765e971c5dc7bbb6b", expectedBatchHash: "257175785213c68b10bb94396b657892fb7ae70708bf98ce357752906a80a6f0"},
		// single chunk blob full
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "4a7e2416aed7aa1630b5dfac5de9f7140f0228a293e6507a98ca762f471bd4cb", expectedy: "39087ba100396ce50ea84f3cb196fd45ce7074888acc57f196b905e3bb4fffda", expectedBlobVersionedHash: "0196c25ea10bafe62aa334122d1e426eccc158423e35272ae009029caf7664b2", expectedBatchHash: "fed7eeba45afa4ac2f658e233adbc7beab27bd7472364a69ab5c16dafe3960b4"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "588908e72f3910e010ecbb38583e3c14d2de20e3fc0fcfca1fa573b6ae652009", expectedy: "4dd0fe025a1d27c21aa3c199e88d8f7bfa839b04e2fffb39d149b7d81ea2d81e", expectedBlobVersionedHash: "0146e7e489077de92fc8e90102560f1ea8d10f3dc5aca0c7ce3f362698e8dfed", expectedBatchHash: "5cd5ae7f3ca9d7777efef7b248fe0348841ea99b270e4c391fa5bed6a00c7aa9"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "6fa8165246ac960a1a31c8f9950dad3c6cfd11393a8822738f392f096e0e27da", expectedy: "3391e91d228eee3a4341c25536741bb3d16387e47ca03548212a4a8acc898dad", expectedBlobVersionedHash: "01a65de32db70380b8728e048ed510cf4fbd9b82ff22955bbc27edebc4fd0188", expectedBatchHash: "f78751f5d548107925e31ace50234e3c926b0ade2aa2bd32f46814016f631d62"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "44c6b024e20a1b616c9619c23b612258ddb5489bb0631119598c89ddb2cf8565", expectedy: "6e3296728e406d16cf1d7342959bcbe0c4e4c1e9b1f705ae6b426a0dbb79838c", expectedBlobVersionedHash: "01cc8fbe921a7c0fb5d01a1e12ef090060740ca1ecebf279f1de3bb4499c7341", expectedBatchHash: "fcca8045e82349c28f6d8747bcd6fec84a34130b31097e2e08e854bc5c21c476"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "4affa105e7c5d72a3223482b237296fead99e6d716b97bab0cb3447f93309692", expectedy: "4a850a8c7b84d568d8505121c92ebf284e88aa7a881290cf3939d52040871e56", expectedBlobVersionedHash: "01d3ce566fbdbcab307095bdc05de7bc2905d25f3dd4453b0f7d5f7ba8da9f08", expectedBatchHash: "ac29c2e8c26749cf99fca994cde6d33147e9e9aa60f162c964720b4937cae8fb"},
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

		patches := gomonkey.NewPatches()
		defer patches.Reset()

		patches.ApplyFunc(convertTxDataToRLPEncoding, func(txData *types.TransactionData) ([]byte, error) {
			data, err := hexutil.Decode(txData.Data)
			if err != nil {
				return nil, err
			}
			return data, nil
		})

		patches.ApplyFunc(checkCompressedDataCompatibility, func(_ []byte) error {
			return nil
		})

		blob, blobVersionedHash, z, _, err := codecv4.(*DACodecV4).constructBlobPayload(chunks, codecv4.MaxNumChunksPerBatch(), true /* enable encode */)
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

		batch := daBatchV3{
			daBatchV0: daBatchV0{
				version:              CodecV4,
				batchIndex:           6789,
				l1MessagePopped:      101,
				totalL1MessagePopped: 10101,
				dataHash:             dataHash,
				parentBatchHash:      common.BytesToHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
			},
			lastBlockTimestamp: 192837,
			blobVersionedHash:  blobVersionedHash,
			blob:               blob,
			z:                  z,
		}
		batch.blobDataProof, err = batch.blobDataProofForPICircuit()
		require.NoError(t, err)
		assert.Equal(t, common.HexToHash(tc.expectedBatchHash), batch.Hash())
	}
}

func TestCodecV4BatchStandardTestCasesDisableCompression(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	// Taking into consideration disabling compression, we allow up to max effective blob bytes.
	// We then ignore the metadata rows for MaxNumChunksPerBatch chunks, plus 1 byte for the compression flag.
	nRowsData := maxEffectiveBlobBytes - (codecv4.MaxNumChunksPerBatch()*4 + 2) - 1

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
		{chunks: [][]string{{}}, expectedz: "04e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb071", expectedy: "5885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", expectedBlobVersionedHash: "016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a", expectedBatchHash: "7c67a67db562e51c9f86f0423275e470e85a214c477b5e01b03ad9bf04390bad"},
		// single non-empty chunk
		{chunks: [][]string{{"0x010203"}}, expectedz: "5f4d24694355a9e3718495c43b24652b0151053f082262fa6e26073c42fd9818", expectedy: "1b69184f2a976099671c3ccffff7a2ea83af24dd578b38956d96d2ac8b8ed74d", expectedBlobVersionedHash: "019d0e2b1297544ce7675246005b5b8db84da926a4ae98001c8272b1e638d3ef", expectedBatchHash: "00d403466e836405efe3041818bf874d4200484f521bb2b684dd7450e7cecbc8"},
		// multiple empty chunks
		{chunks: [][]string{{}, {}}, expectedz: "14160c76e0d43a3cf37faa4c24f215b9c3349d5709b84332da80ca0667ece780", expectedy: "6407aa706069f09c7b6481ea00a489f74e96673a39e197c6f34b30f2d1f9fe23", expectedBlobVersionedHash: "0190689489894e430d08513202be679dcce47e3ae77bac13e1750a99d15b9a1c", expectedBatchHash: "b5ee4048b5f05dbdecc7a49f1698a0e911c64224ebaf5f538547973223ac1cd1"},
		// multiple non-empty chunks
		{chunks: [][]string{{"0x010203"}, {"0x070809"}}, expectedz: "15ac8e175330a67d2bd8018a486ee1fbbcead23efd4f2e57cd94312cfb7830b1", expectedy: "12593c94d52eaed8be4b79f62397e86b3b75c2af6197533e5a917676e551ce26", expectedBlobVersionedHash: "01972ce3c3b894e9c381f2eed5395809eb7a762eb0c28b4beb73ac3c73ebd3f8", expectedBatchHash: "ae2893806a3dd7449c5bc10c47500f5df96e5cffdffe083171cb7ee908411e28"},
		// empty chunk followed by non-empty chunk
		{chunks: [][]string{{}, {"0x010203"}}, expectedz: "49ebeb74372d05b335f05d0e48f3155955c27ec9cac92a03a9d85050e24efdd6", expectedy: "7088f4810a4d61bcadcdf2debff998027eb10caa70474db18a8228ef4edc6cd7", expectedBlobVersionedHash: "015ea2df6fc4582fd704ae55157c1311f2d680240c8b8805e3435856a15da91b", expectedBatchHash: "cf4bee00c5e044bc6c9c168a3245f8edfcdeac602d63b2e75b45faa7b95d8c16"},
		// non-empty chunk followed by empty chunk
		{chunks: [][]string{{"0x070809"}, {}}, expectedz: "2374a8bcd2fcbfae4cc43a5e21a0c69cd206071e46db2c8a3c9bb7e9b8c60120", expectedy: "51b51d261d897e81e94498493b70ec425320002d9390be69b63c87e22871d5bf", expectedBlobVersionedHash: "01600a0cb0fb308f1202172f88764bafa9deddab52331a38e767267b6785d2a3", expectedBatchHash: "53cc0ff17ca71e1711f6b261537fc8da28a5d289325be33d5286920417fe9a6e"},
		// max number of chunks all empty
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}, expectedz: "6908503d26b56b1eb9c94d25e8e5d6e8a14e48d3ac38b063d2bc20c25a361fb5", expectedy: "22d016c0d7ef4d74e371522a9da62a43bcf2dc69be21e4133d35bf8e6fe44f68", expectedBlobVersionedHash: "01baf85d7d36b7d7df4c684b78fa5d3f94dd893f92c8c4cc8ee26a67b2fce588", expectedBatchHash: "7585f286302ba26219b1229da0fd1f557f465fb244bd1839eef95df1d75f1457"},
		// max number of chunks all non-empty
		{chunks: [][]string{
			{"0x0a"},
			{"0x0a0b"},
			{"0x0a0b0c"},
			{"0x0a0b0c0d"},
			{"0x0a0b0c0d0e"},
			{"0x0a0b0c0d0e0f"},
			{"0x0a0b0c0d0e0f10"},
			{"0x0a0b0c0d0e0f1011"},
			{"0x0a0b0c0d0e0f101112"},
			{"0x0a0b0c0d0e0f10111213"},
			{"0x0a0b0c0d0e0f1011121314"},
			{"0x0a0b0c0d0e0f101112131415"},
			{"0x0a0b0c0d0e0f10111213141516"},
			{"0x0a0b0c0d0e0f1011121314151617"},
			{"0x0a0b0c0d0e0f101112131415161718"},
			{"0x0a0b0c0d0e0f10111213141516171819"},
			{"0x0a0b0c0d0e0f101112131415161718191a"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435"},
			{"0x0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"},
		}, expectedz: "5fcba58abcc9a0ae4a3780a2a621e57e8f8c5d323134aa9623579e698e4d18b1", expectedy: "69570d3c97e9573b5529b213055b814d5e4b7dda2bb2c3a7d06456c157ab338d", expectedBlobVersionedHash: "018cd2721e76c37374e450382e2e53faa24393cfbcbbe134e1756392c8f1a4fc", expectedBatchHash: "52948b79f4457473836b44ea9bbb2c6fc61b5937fc881b95b2baa78af0e0623b"},
		// single chunk blob full
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "53dde3d5fe1a53f364a8a865e746d3c7ca7fadadbdb816c30b49958057f1e9d9", expectedy: "3c1f69a7180f98a8a39f26189ee73fca4fbc41ca91a5ae02b521625bd67628e7", expectedBlobVersionedHash: "01d9acf02b1ef5213e0bd530e1cf99d2a19f622318bf3d97c7ec693aa3a7fdb1", expectedBatchHash: "b9411a190cc9db47fd31c009efb7b2275c235f511780f0ed6874242cb2eb7b72"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "1843d3229313afb023d210a0be73f64fba2fe20b7ae14b2e1df37ebe32f55afa", expectedy: "29db4ab0e596593fad50784a3a6f802ba1d9daf760c09f64bdc3d1899b247d97", expectedBlobVersionedHash: "01e337f571c6079bb6c89dab463ff3b6b2b5139fbd4f5446996fea8c0df94c65", expectedBatchHash: "56ce765d11a10b89fb412c293756299fd803485aca595c6de8a35c790486f62c"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "3df579b9d11368e712b9b23318e8ea2dfcc5d5a647b16fb8254d017b8804f4b1", expectedy: "4da6e30ac69fb2d65de9b9306de0fa15a2cee87aee245e831f313366c0809b46", expectedBlobVersionedHash: "01641976b8a50f5aa3d277f250904caae681a4e090e867c6abdbfe03e216003a", expectedBatchHash: "5160fc712e9dbaa52396b7662f2e393533a5b25457e5ca9475bc8fd27f24d78a"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "47ca3393ebaef699800bd666ff119c1978e938e04d22c9a024a1b17f523281f9", expectedy: "380704fe5da08d69a94c8af57f17153076f6eb20d5e69c60b343fb66c6266101", expectedBlobVersionedHash: "014aac5dbd6f5456f68635c6674caa374faa0dbe012c5800e0364749485bf1bf", expectedBatchHash: "c674d48d3a9146049b1ea2993d5cc070dd76617fa550234563591c366654d6c6"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "501e762800ca76490b61114d8a84a12f1f72fce71252f7c294a5f5b4190da6b1", expectedy: "524e879ce867b79cbeffd8aa5241731f5562addfc246dda20bb857eb55158399", expectedBlobVersionedHash: "01504b1eb6894cc96a8cac8f02fba838c086171cbb879ccd9cdeb44f9d4237f5", expectedBatchHash: "59a97a5d8e4206bb283b524b2d48a707c8869c87dea6563dd99dcb367bed6412"},
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

		patches := gomonkey.NewPatches()
		defer patches.Reset()

		patches.ApplyFunc(convertTxDataToRLPEncoding, func(txData *types.TransactionData) ([]byte, error) {
			data, err := hexutil.Decode(txData.Data)
			if err != nil {
				return nil, err
			}
			return data, nil
		})

		patches.ApplyFunc(checkCompressedDataCompatibility, func(_ []byte) error {
			return nil
		})

		blob, blobVersionedHash, z, _, err := codecv4.(*DACodecV4).constructBlobPayload(chunks, codecv4.MaxNumChunksPerBatch(), false /* disable encode */)
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

		batch := daBatchV3{
			daBatchV0: daBatchV0{
				version:              CodecV4,
				batchIndex:           6789,
				l1MessagePopped:      101,
				totalL1MessagePopped: 10101,
				dataHash:             dataHash,
				parentBatchHash:      common.BytesToHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
			},
			lastBlockTimestamp: 192837,
			blobVersionedHash:  blobVersionedHash,
			blob:               blob,
			z:                  z,
		}
		batch.blobDataProof, err = batch.blobDataProofForPICircuit()
		require.NoError(t, err)
		assert.Equal(t, common.HexToHash(tc.expectedBatchHash), batch.Hash())
	}
}

func TestDACodecV4SimpleMethods(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	t.Run("Version", func(t *testing.T) {
		version := codecv4.Version()
		assert.Equal(t, CodecV4, version)
	})
}

func TestCodecV4ChunkCompressedDataCompatibilityCheck(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	// chunk with a single empty block
	emptyBlock := &Block{}
	emptyChunk := &Chunk{Blocks: []*Block{emptyBlock}}

	compatible, err := codecv4.CheckChunkCompressedDataCompatibility(emptyChunk)
	assert.NoError(t, err)
	assert.Equal(t, false, compatible)

	txChunk := &Chunk{
		Blocks: []*Block{
			{
				Transactions: []*types.TransactionData{
					{Type: types.L1MessageTxType},
				},
			},
		},
	}
	compatible, err = codecv4.CheckChunkCompressedDataCompatibility(txChunk)
	assert.NoError(t, err)
	assert.Equal(t, false, compatible)

	testCases := []struct {
		name             string
		jsonFile         string
		expectCompatible bool
	}{
		{"Block 02", "testdata/blockTrace_02.json", true},
		{"Block 03", "testdata/blockTrace_03.json", true},
		{"Block 04", "testdata/blockTrace_04.json", true},
		{"Block 05", "testdata/blockTrace_05.json", false},
		{"Block 06", "testdata/blockTrace_06.json", false},
		{"Block 07", "testdata/blockTrace_07.json", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block := readBlockFromJSON(t, tc.jsonFile)
			chunk := &Chunk{Blocks: []*Block{block}}
			compatible, err := codecv4.CheckChunkCompressedDataCompatibility(chunk)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectCompatible, compatible)
		})
	}
}

func TestCodecV4BatchCompressedDataCompatibilityCheck(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	require.NoError(t, err)

	// empty batch
	emptyBatch := &Batch{}
	compatible, err := codecv4.CheckBatchCompressedDataCompatibility(emptyBatch)
	assert.NoError(t, err)
	assert.Equal(t, false, compatible)

	testCases := []struct {
		name             string
		jsonFiles        []string
		expectCompatible bool
	}{
		{"Single Block 02", []string{"testdata/blockTrace_02.json"}, true},
		{"Single Block 03", []string{"testdata/blockTrace_03.json"}, true},
		{"Single Block 04", []string{"testdata/blockTrace_04.json"}, true},
		{"Single Block 05", []string{"testdata/blockTrace_05.json"}, false},
		{"Single Block 06", []string{"testdata/blockTrace_06.json"}, false},
		{"Single Block 07", []string{"testdata/blockTrace_07.json"}, false},
		{"Multiple Blocks", []string{"testdata/blockTrace_02.json", "testdata/blockTrace_03.json", "testdata/blockTrace_04.json", "testdata/blockTrace_05.json", "testdata/blockTrace_06.json", "testdata/blockTrace_07.json"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var chunks []*Chunk
			for _, jsonFile := range tc.jsonFiles {
				block := readBlockFromJSON(t, jsonFile)
				chunks = append(chunks, &Chunk{Blocks: []*Block{block}})
			}
			batch := &Batch{Chunks: chunks}
			compatible, err := codecv4.CheckBatchCompressedDataCompatibility(batch)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectCompatible, compatible)
		})
	}
}
