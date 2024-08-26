package codecv4

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv0"
)

func TestCodecV4BlockEncode(t *testing.T) {
	block := &DABlock{}
	encoded := hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	block, err := NewDABlock(trace2, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(block.Encode())
	assert.Equal(t, "00000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	block, err = NewDABlock(trace3, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(block.Encode())
	assert.Equal(t, "00000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	block, err = NewDABlock(trace4, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	block, err = NewDABlock(trace5, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	block, err = NewDABlock(trace6, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	block, err = NewDABlock(trace7, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)

	// sanity check: v0 and v4 block encodings are identical
	for _, trace := range []*encoding.Block{trace2, trace3, trace4, trace5, trace6, trace7} {
		blockv0, err := codecv0.NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv0 := hex.EncodeToString(blockv0.Encode())

		blockv4, err := NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv4 := hex.EncodeToString(blockv4.Encode())

		assert.Equal(t, encodedv0, encodedv4)
	}
}

func TestCodecV4ChunkEncode(t *testing.T) {
	// chunk with a single empty block
	block := DABlock{}
	chunk := &DAChunk{Blocks: []*DABlock{&block}, Transactions: [][]*types.TransactionData{nil}}
	encoded := hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	// transactions are not part of the encoding
	chunk.Transactions[0] = append(chunk.Transactions[0], &types.TransactionData{Type: types.L1MessageTxType}, &types.TransactionData{Type: types.DynamicFeeTxType})
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	originalChunk := &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err := NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "0100000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	trace = readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "0100000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	trace = readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "01000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	trace = readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	trace = readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	trace = readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(chunk.Encode())
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)
}

func TestCodecV4ChunkHash(t *testing.T) {
	// chunk with a single empty block
	block := DABlock{}
	chunk := &DAChunk{Blocks: []*DABlock{&block}, Transactions: [][]*types.TransactionData{nil}}
	hash, err := chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x7cdb9d7f02ea58dfeb797ed6b4f7ea68846e4f2b0e30ed1535fc98b60c4ec809", hash.Hex())

	// L1 transactions are part of the hash
	chunk.Transactions[0] = append(chunk.Transactions[0], &types.TransactionData{Type: types.L1MessageTxType, TxHash: "0x0000000000000000000000000000000000000000000000000000000000000000"})
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xdcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2", hash.Hex())

	// L2 transactions are not part of the hash
	chunk.Transactions[0] = append(chunk.Transactions[0], &types.TransactionData{Type: types.DynamicFeeTxType, TxHash: "0x0000000000000000000000000000000000000000000000000000000000000000"})
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xdcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2", hash.Hex())

	// numL1Messages are not part of the hash
	chunk.Blocks[0].NumL1Messages = 1
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xdcb42a70c54293e75a19dd1303d167822182d78b361dd7504758c35e516871b2", hash.Hex())

	// invalid hash
	chunk.Transactions[0] = append(chunk.Transactions[0], &types.TransactionData{Type: types.L1MessageTxType, TxHash: "0xg"})
	_, err = chunk.Hash()
	assert.Error(t, err)

	trace := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	originalChunk := &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x820f25d806ddea0ccdbfa463ee480da5b6ea3906e8a658417fb5417d0f837f5c", hash.Hex())

	trace = readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x4620b3900e8454133448b677cbb2054c5dd61d467d7ebf752bfb12cffff90f40", hash.Hex())

	trace = readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x059c6451e83012b405c7e1a38818369012a4a1c87d7d699366eac946d0410d73", hash.Hex())

	trace = readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x854fc3136f47ce482ec85ee3325adfa16a1a1d60126e1c119eaaf0c3a9e90f8e", hash.Hex())

	trace = readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x2aa220ca7bd1368e59e8053eb3831e30854aa2ec8bd3af65cee350c1c0718ba6", hash.Hex())

	trace = readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	originalChunk = &encoding.Chunk{Blocks: []*encoding.Block{trace}}
	chunk, err = NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xb65521bea7daff75838de07951c3c055966750fb5a270fead5e0e727c32455c3", hash.Hex())
}

func TestCodecV4BatchEncode(t *testing.T) {
	// empty batch
	batch := &DABatch{Version: uint8(encoding.CodecV4)}
	encoded := hex.EncodeToString(batch.Encode())
	assert.Equal(t, "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "040000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101e5c897e0f98f6addd6c99bb51ff927cde93851b0d407aae3d7d5de75a31f2900000000000000000000000000000000000000000000000000000000000000000000000063807b2a26451ed31542ed15543973f8bc8c3b6382ba0cba5650a7faf14625377029203c1b6db22aa24613cb68dee10ca50bbbc88fc15b8a6abf9dcf3ad382a2642e480d", encoded)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "04000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a601ad8c8eee24cc98ab1ca9c0a4c92bf20f488f06dedbc22f1312bd389df7105000000000000000000000000000000000000000000000000000000000000000000000000063807b2d30702c0ea39553a0601a9c6fc5b27c076ddfc1044001fb0a8ad1fd9016304a61233de2770e0fb9a5578e5f633846ef9fa4c2ab8b80b8f9a30f09be07cda8d725", encoded)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "040000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f01c6a9a7d06425dbfad42697e4ce5bc8562d7c5ffe1f62d57fcb51240e33af93000000000000000000000000000000000000000000000000000000000000000000000000646b6e1338122423f3cebb92645f9ac93c8ee50edb75ea93a951f278007e721a7b9f995824895b00195499dfe77d201cf3627050d866abb2685f87e10466c4fcaf3a8588", encoded)

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a000000000000000000000000000000000000000000000000000000000000000000000000646b6ed004e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", encoded)

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "040000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a000000000000000000000000000000000000000000000000000000000000000000000000646b6ed004e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", encoded)

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "04000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208016ac24dabb9e1bbb3ec3c65b50a829564c2f56160ba92fbdb03ed7e4a0c439a000000000000000000000000000000000000000000000000000000000000000000000000646b6ed004e124536a56f650b0994e58647e59087bf99ecadbd7bc730ad6290f229fb0715885a06aad250ef3594c65a7a6a0e282175b1ad4d8b4063dac48e282bb5a9213", encoded)

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d80113ba3d5c53a035f4b4ec6f8a2ba9ab521bccab9f90e3a713ab5fffc0adec57000000000000000000000000000000000000000000000000000000000000000000000000646b6ed012e49b70b64652e5cab5dfdd1f58958d863de1d7fcb959e09f147a98b0b895171560f81b17ec3a2fe1c8ed2d308ca5bf002d7e3c18db9682a8d0f5379bf213aa", encoded)

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e1347670121388d141bd439af8447db5d00bacbfe1587fea6581f795e98588d95ba7f26000000000000000000000000000000000000000000000000000000000000000000000000646b6ed046aedf214a661b6b37b9c325fef4484ff3613a6fb52719609bf02a66bc7ba23b6e9b7bcbe3be0ba95654f16f715bf7e39ef87a84199340423f6487cf56058085", encoded)
}

func TestCodecV4BatchHash(t *testing.T) {
	// empty batch
	batch := &DABatch{Version: uint8(encoding.CodecV4)}
	assert.Equal(t, "0xdaf0827d02b32d41458aea0d5796dd0072d0a016f9834a2cb1a964d2c6ee135c", batch.Hash().Hex())

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x53d6da35c9b6f0413b6ebb80f4a8c19b0e3279481ddf602398a54d3b4e5d4f2c", batch.Hash().Hex())

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x08feefdb19215bb0f51f85a3b02a0954ac7da67681e274db49b9102f4c6e0857", batch.Hash().Hex())

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0xc56c5e51993342232193d1d93124bae30a5b1444eebf49b2dd5f2c5962d4d54d", batch.Hash().Hex())

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x2c32177c8b4c6289d977361c7fd0f1a6ea15add64da2eb8caf0420ac9b35231e", batch.Hash().Hex())

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x909bebbebdbf5ba9c85c6894e839c0b044d2878c457c4942887e3d64469ad342", batch.Hash().Hex())

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x53765a37bbd72655df586b530d79cb4ad0fb814d72ddc95e01e0ede579f45117", batch.Hash().Hex())

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x74ccf9cc265f423cc6e6e53ed294000637a832cdc93c76485855289bebb6764a", batch.Hash().Hex())

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, "0x8d5ee00a80d7dbdc083d0cdedd35c2cb722e5944f9d88f7450c9186f3ef3da44", batch.Hash().Hex())
}

func TestCodecV4ChunkAndBatchCommitGasEstimation(t *testing.T) {
	block2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{block2}}
	chunk2Gas := EstimateChunkL1CommitGas(chunk2)
	assert.Equal(t, uint64(51124), chunk2Gas)
	batch2 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch2Gas := EstimateBatchL1CommitGas(batch2)
	assert.Equal(t, uint64(207649), batch2Gas)

	block3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{block3}}
	chunk3Gas := EstimateChunkL1CommitGas(chunk3)
	assert.Equal(t, uint64(51124), chunk3Gas)
	batch3 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch3Gas := EstimateBatchL1CommitGas(batch3)
	assert.Equal(t, uint64(207649), batch3Gas)

	block4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{block4}}
	chunk4Gas := EstimateChunkL1CommitGas(chunk4)
	assert.Equal(t, uint64(53745), chunk4Gas)
	batch4 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch4Gas := EstimateBatchL1CommitGas(batch4)
	assert.Equal(t, uint64(210302), batch4Gas)

	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{block2, block3}}
	chunk5Gas := EstimateChunkL1CommitGas(chunk5)
	assert.Equal(t, uint64(52202), chunk5Gas)
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{block4}}
	chunk6Gas := EstimateChunkL1CommitGas(chunk6)
	assert.Equal(t, uint64(53745), chunk6Gas)
	batch5 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk5, chunk6}}
	batch5Gas := EstimateBatchL1CommitGas(batch5)
	assert.Equal(t, uint64(213087), batch5Gas)
}

func repeat(element byte, count int) string {
	result := make([]byte, 0, count)
	for i := 0; i < count; i++ {
		result = append(result, element)
	}
	return "0x" + common.Bytes2Hex(result)
}

func TestCodecV4BatchStandardTestCases(t *testing.T) {
	// Taking into consideration compression, we allow up to 5x of max blob bytes.
	// We then ignore the metadata rows for 45 chunks.
	maxChunks := 45
	nRowsData := 5*126976 - (maxChunks*4 + 2)

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
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "37ca5366d9f5ddd9471f074f8019050ea6a13097368e84f298ffa1bd806ad851", expectedy: "5aa602da97cc438a039431c799b5f97467bcd45e693273dd1215f201b19fa5bd", expectedBlobVersionedHash: "01e531e7351a271839b2ae6ddec58818efd5f426fd6a7c0bc5c33c9171ed74bf", expectedBatchHash: "d3809d6b2fd10a62c6c58f9e7c32772f4ac062a78d363f46cd3ee301e87dbad2"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "250fc907e7ba3b5affb90a624566e337b02dd89a265677571cc0d1c51b60af19", expectedy: "1b2898bb001d962717159f49b015ae7228b21e9a590f836be0d79a0870c7d82b", expectedBlobVersionedHash: "01f3c431a72bbfd43c42dbd638d7f6d109be2b9449b96386b214f92b9e28ccc4", expectedBatchHash: "a51631991f6210b13e9c8ac9260704cca29fdc08adcfbd210053dc77c956e82f"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "6ba09c6123b374f1828ce5b3e52c69ac7e2251f1a573ba4d51e71b386eef9c38", expectedy: "3104f9e81ecf4ade3281cc8ea68c4f451341388e2a2c84be4b5e5ed938b6bb26", expectedBlobVersionedHash: "017813036e3c57d5259d5b1d89ca0fe253e43d740f5ee287eabc916b3486f15d", expectedBatchHash: "ebfaf617cc91d9147b00968263993f70e0efc57c1189877092a87ea60b55a2d7"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "295f6ba39b866f6635a1e11ffe16badf42174ba120bdcb973806620370f665fc", expectedy: "553772861d517aefd58332d87d75a388523b40dbd69c1d73b7d78fd18d895513", expectedBlobVersionedHash: "013a5cb4a098dfa068b82acea202eac5c7b1ec8f16c7cb37b2a9629e7359a4b1", expectedBatchHash: "b4c58eb1be9b2b21f6a43b4170ee92d6ee0af46e20848fff508a07d40b2bac29"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "4affa105e7c5d72a3223482b237296fead99e6d716b97bab0cb3447f93309692", expectedy: "4a850a8c7b84d568d8505121c92ebf284e88aa7a881290cf3939d52040871e56", expectedBlobVersionedHash: "01d3ce566fbdbcab307095bdc05de7bc2905d25f3dd4453b0f7d5f7ba8da9f08", expectedBatchHash: "ac29c2e8c26749cf99fca994cde6d33147e9e9aa60f162c964720b4937cae8fb"},
	} {
		chunks := []*encoding.Chunk{}

		for _, c := range tc.chunks {
			block := &encoding.Block{Transactions: []*types.TransactionData{}}

			for _, data := range c {
				tx := &types.TransactionData{Type: 0xff, Data: data}
				block.Transactions = append(block.Transactions, tx)
			}

			chunk := &encoding.Chunk{Blocks: []*encoding.Block{block}}
			chunks = append(chunks, chunk)
		}

		blob, blobVersionedHash, z, _, err := ConstructBlobPayload(chunks, true /* enable encode */, true /* use mock */)
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
			copy(dataBytes[32*i:32*i+32], []byte{255 - uint8(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		}
		dataHash := crypto.Keccak256Hash(dataBytes)

		batch := DABatch{
			Version:              uint8(encoding.CodecV4),
			BatchIndex:           6789,
			L1MessagePopped:      101,
			TotalL1MessagePopped: 10101,
			DataHash:             dataHash,
			BlobVersionedHash:    blobVersionedHash,
			ParentBatchHash:      common.BytesToHash([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
			LastBlockTimestamp:   192837,
			blob:                 blob,
			z:                    z,
		}

		batch.BlobDataProof, err = batch.blobDataProofForPICircuit()
		require.NoError(t, err)

		assert.Equal(t, common.HexToHash(tc.expectedBatchHash), batch.Hash())
	}
}

func TestCodecV4BatchL1MessagePopped(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 0, int(batch.L1MessagePopped))
	assert.Equal(t, 0, int(batch.TotalL1MessagePopped))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 0, int(batch.L1MessagePopped))
	assert.Equal(t, 0, int(batch.TotalL1MessagePopped))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 11, int(batch.L1MessagePopped)) // skip 10, include 1
	assert.Equal(t, 11, int(batch.TotalL1MessagePopped))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 42, int(batch.L1MessagePopped)) // skip 37, include 5
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 37
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 5, int(batch.L1MessagePopped)) // skip 37, include 5
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 10, int(batch.L1MessagePopped)) // skip 7, include 3
	assert.Equal(t, 10, int(batch.TotalL1MessagePopped))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 257, int(batch.L1MessagePopped)) // skip 255, include 2
	assert.Equal(t, 257, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 1
	batch, err = NewDABatch(originalBatch, false /* disable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 256, int(batch.L1MessagePopped)) // skip 254, include 2
	assert.Equal(t, 257, int(batch.TotalL1MessagePopped))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}} // queue index 10
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}                 // queue index 37-41
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 42, int(batch.L1MessagePopped))
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 10
	batch, err = NewDABatch(originalBatch, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, 32, int(batch.L1MessagePopped))
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))
}

func TestCodecV4ChunkAndBatchBlobSizeEstimation(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	chunk2BatchBytesSize, chunk2BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk2, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), chunk2BatchBytesSize)
	assert.Equal(t, uint64(238), chunk2BlobSize)
	batch2 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch2BatchBytesSize, batch2BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch2, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), batch2BatchBytesSize)
	assert.Equal(t, uint64(238), batch2BlobSize)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	chunk3BatchBytesSize, chunk3BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk3, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), chunk3BatchBytesSize)
	assert.Equal(t, uint64(2934), chunk3BlobSize)
	batch3 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch3BatchBytesSize, batch3BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch3, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), batch3BatchBytesSize)
	assert.Equal(t, uint64(2934), batch3BlobSize)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk4BatchBytesSize, chunk4BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk4, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk4BatchBytesSize)
	assert.Equal(t, uint64(55), chunk4BlobSize)
	batch4 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	blob4BatchBytesSize, batch4BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch4, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), blob4BatchBytesSize)
	assert.Equal(t, uint64(55), batch4BlobSize)

	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3}}
	chunk5BatchBytesSize, chunk5BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk5, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6093), chunk5BatchBytesSize)
	assert.Equal(t, uint64(3150), chunk5BlobSize)
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk6BatchBytesSize, chunk6BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk6, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk6BatchBytesSize)
	assert.Equal(t, uint64(55), chunk6BlobSize)
	batch5 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk5, chunk6}}
	batch5BatchBytesSize, batch5BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch5, true /* enable encode */)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6125), batch5BatchBytesSize)
	assert.Equal(t, uint64(3187), batch5BlobSize)
}

func TestCodecV4ChunkAndBatchCalldataSizeEstimation(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	chunk2CalldataSize := EstimateChunkL1CommitCalldataSize(chunk2)
	assert.Equal(t, uint64(60), chunk2CalldataSize)
	batch2 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch2CalldataSize := EstimateBatchL1CommitCalldataSize(batch2)
	assert.Equal(t, uint64(60), batch2CalldataSize)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	chunk3CalldataSize := EstimateChunkL1CommitCalldataSize(chunk3)
	assert.Equal(t, uint64(60), chunk3CalldataSize)
	batch3 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch3CalldataSize := EstimateBatchL1CommitCalldataSize(batch3)
	assert.Equal(t, uint64(60), batch3CalldataSize)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk4CalldataSize := EstimateChunkL1CommitCalldataSize(chunk4)
	assert.Equal(t, uint64(60), chunk4CalldataSize)
	batch4 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch4CalldataSize := EstimateBatchL1CommitCalldataSize(batch4)
	assert.Equal(t, uint64(60), batch4CalldataSize)

	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3}}
	chunk5CalldataSize := EstimateChunkL1CommitCalldataSize(chunk5)
	assert.Equal(t, uint64(120), chunk5CalldataSize)
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk6CalldataSize := EstimateChunkL1CommitCalldataSize(chunk6)
	assert.Equal(t, uint64(60), chunk6CalldataSize)
	batch5 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk5, chunk6}}
	batch5CalldataSize := EstimateBatchL1CommitCalldataSize(batch5)
	assert.Equal(t, uint64(180), batch5CalldataSize)
}

func TestCodecV4DABatchJSONMarshalUnmarshal(t *testing.T) {
	t.Run("Case 1", func(t *testing.T) {
		jsonStr := `{
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

		var batch DABatch
		err := json.Unmarshal([]byte(jsonStr), &batch)
		require.NoError(t, err)

		assert.Equal(t, uint8(4), batch.Version)
		assert.Equal(t, uint64(293212), batch.BatchIndex)
		assert.Equal(t, uint64(7), batch.L1MessagePopped)
		assert.Equal(t, uint64(904750), batch.TotalL1MessagePopped)
		assert.Equal(t, common.HexToHash("0xa261ff31f8f78c19f65d14d6394eb911d53a3a3add9a9691b211caa5809be450"), batch.DataHash)
		assert.Equal(t, common.HexToHash("0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e"), batch.BlobVersionedHash)
		assert.Equal(t, common.HexToHash("0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee"), batch.ParentBatchHash)
		assert.Equal(t, uint64(1721130505), batch.LastBlockTimestamp)
		assert.Equal(t, common.HexToHash("0x496b144866cffedfd71423639984bf0d9ad4309ff7e35693f1baef3cdaf1471e"), batch.BlobDataProof[0])
		assert.Equal(t, common.HexToHash("0x5eba7d42db109bfa124d1bc4dbcb421944b8aae6eae13a9d55eb460ce402785b"), batch.BlobDataProof[1])

		batchHash := batch.Hash()

		expectedHash := common.HexToHash("0x64ba42153a4f642b2d8a37cf74a53067c37bba7389b85e7e07521f584e6b73d0")
		assert.Equal(t, expectedHash, batchHash, "Batch hash does not match expected value")

		// Marshal and Unmarshal test
		data, err := json.Marshal(&batch)
		require.NoError(t, err)

		var decodedBatch DABatch
		err = json.Unmarshal(data, &decodedBatch)
		require.NoError(t, err)

		assert.Equal(t, batch, decodedBatch)
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

		var batch DABatch
		err := json.Unmarshal([]byte(jsonStr), &batch)
		require.NoError(t, err)

		assert.Equal(t, uint8(5), batch.Version)
		assert.Equal(t, uint64(123), batch.BatchIndex)
		assert.Equal(t, uint64(0), batch.L1MessagePopped)
		assert.Equal(t, uint64(0), batch.TotalL1MessagePopped)
		assert.Equal(t, common.HexToHash("0xabacadaeaf000000000000000000000000000000000000000000000000000000"), batch.ParentBatchHash)
		assert.Equal(t, uint64(1720174236), batch.LastBlockTimestamp)
		assert.Equal(t, common.HexToHash("0xa1a518fa8e636dcb736629c296ed10341536c4cf850a3bc0a808d8d66d7f1ee6"), batch.DataHash)
		assert.Equal(t, common.HexToHash("0x01c61b784ba4cd0fd398717fdc3470729d1a28d70632d520174c9e47614c80e1"), batch.BlobVersionedHash)
		assert.Equal(t, common.HexToHash("0x1ee03153fd007529c214a68934b2cfd51e8586bd142e157564328946a0fc8899"), batch.BlobDataProof[0])
		assert.Equal(t, common.HexToHash("0x118e196a9432c84c53db5a5a7bfbe13ef1ff8ffdba12fbccaf6360110eb71a10"), batch.BlobDataProof[1])

		batchHash := batch.Hash()

		expectedHash := common.HexToHash("0xd14f142dbc5c384e9920d5bf82c6bbf7c98030ffd7a3cace6c8a6e9639a285f9")
		assert.Equal(t, expectedHash, batchHash, "Batch hash does not match expected value")

		// Marshal and Unmarshal test
		data, err := json.Marshal(&batch)
		require.NoError(t, err)

		var decodedBatch DABatch
		err = json.Unmarshal(data, &decodedBatch)
		require.NoError(t, err)

		assert.Equal(t, batch, decodedBatch)
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

		var batch DABatch
		err := json.Unmarshal([]byte(jsonStr), &batch)
		require.NoError(t, err)

		assert.Equal(t, uint8(4), batch.Version)
		assert.Equal(t, uint64(293205), batch.BatchIndex)
		assert.Equal(t, uint64(0), batch.L1MessagePopped)
		assert.Equal(t, uint64(904737), batch.TotalL1MessagePopped)
		assert.Equal(t, common.HexToHash("0x053c0f8b8bea2f7f98dd9dcdc743f1059ca664b2b72a21381b7184dd8aa922e0"), batch.ParentBatchHash)
		assert.Equal(t, uint64(1721129563), batch.LastBlockTimestamp)
		assert.Equal(t, common.HexToHash("0x84786e890c015721a37f02a010bd2b84eaf4363cdf04831628a38ddbf497d0bf"), batch.DataHash)
		assert.Equal(t, common.HexToHash("0x013c7e2c9ee9cd6511e8952e55ce5568832f8be3864de823d4ead5f6dfd382ae"), batch.BlobVersionedHash)
		assert.Equal(t, common.HexToHash("0x519fb200d451fea8623ea1bdb15d8138cea68712792a92b9cf1f79dae6df5b54"), batch.BlobDataProof[0])
		assert.Equal(t, common.HexToHash("0x6d50a85330192c8e835cbd6bcdff0f2f23b0b3822e4e0319c92dafd70f0e21da"), batch.BlobDataProof[1])

		batchHash := batch.Hash()

		expectedHash := common.HexToHash("0x19638ca802926b93946fe281666205958838d46172587d150ca4c720ae244cd3")
		assert.Equal(t, expectedHash, batchHash, "Batch hash does not match expected value")

		// Marshal and Unmarshal test
		data, err := json.Marshal(&batch)
		require.NoError(t, err)

		var decodedBatch DABatch
		err = json.Unmarshal(data, &decodedBatch)
		require.NoError(t, err)

		assert.Equal(t, batch, decodedBatch)
	})
}

func readBlockFromJSON(t *testing.T, filename string) *encoding.Block {
	data, err := os.ReadFile(filename)
	assert.NoError(t, err)

	block := &encoding.Block{}
	assert.NoError(t, json.Unmarshal(data, block))
	return block
}
