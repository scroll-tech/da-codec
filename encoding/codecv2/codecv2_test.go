package codecv2

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/crypto/kzg4844"
	"github.com/stretchr/testify/assert"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv0"
)

func TestCodecV2BlockEncode(t *testing.T) {
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

	// sanity check: v0 and v1 block encodings are identical
	for _, trace := range []*encoding.Block{trace2, trace3, trace4, trace5, trace6, trace7} {
		blockv0, err := codecv0.NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv0 := hex.EncodeToString(blockv0.Encode())

		blockv1, err := NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv1 := hex.EncodeToString(blockv1.Encode())

		assert.Equal(t, encodedv0, encodedv1)
	}
}

func TestCodecV2ChunkEncode(t *testing.T) {
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

func TestCodecV2ChunkHash(t *testing.T) {
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

func TestCodecV1BatchEncode(t *testing.T) {
	// empty batch
	batch := &DABatch{Version: CodecV2Version}
	encoded := hex.EncodeToString(batch.Encode())
	assert.Equal(t, "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "020000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed541017b541197faa5cc281dc0ea3998955894598e6323f3219c3d1e4beaf4f654040000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "02000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a601dc002f94d442ea74ddfd3a595f225f50861a5eb0ab6122db4916e30a251f250000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "020000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f01416a70c569f7e638cc95d50c41c3e03eef3a487e83b1f2e1d8c2ca7b27e779000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ff", encoded)

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "020000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4015742f91b85b27644dcdc4177b705cdd5d6c8c1dd3c82ad77eda5623387da5a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffff", encoded)

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "020000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d015742f91b85b27644dcdc4177b705cdd5d6c8c1dd3c82ad77eda5623387da5a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001dd", encoded)

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "02000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208015742f91b85b27644dcdc4177b705cdd5d6c8c1dd3c82ad77eda5623387da5a0000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0000000000000000000000000000000000000000000000000000000000000000", encoded)

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "020000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d801b3f2c6d6f17b41067d6ea3d7575453b5377e6fb251380340a3d6e97d32400b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "020000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e13476701795981f4ed52897102965ce76defc953c45835a947f4efe2957b0d29d476ae00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)
}

func TestCodecV1BatchHash(t *testing.T) {
	// empty batch
	batch := &DABatch{Version: CodecV2Version}
	assert.Equal(t, "0x8839b8a7b8dfebdc8e829f6fe543578ccdc8da1307e1e1581541a1e2a8fa5592", batch.Hash().Hex())

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x1e5bf07cdcb21f4bd779680a86d36277e6f4cccf9f506dc5e3aae9837b108779", batch.Hash().Hex())

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xd86ccb7e387bc83f3f9d3184cb2417bd1e027dce339d528f32b999811d20ae2a", batch.Hash().Hex())

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x8b129cba10ff15d6af580f7142fbc6ab8cc58f15e7b5a43f719dbc1dbd4e1d17", batch.Hash().Hex())

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xbc6d2c1d6a5777ead777024cd2f4daccee8a10b6692270a99f2ddcec0c807b8f", batch.Hash().Hex())

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x4f236b6da94327f11ea11db44b23b7a9fc09769b2faecd2ae1d6be5bc4e41362", batch.Hash().Hex())

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x6530f04cf596ec59507d564851837d07e235a148e4b46be2a29a2b3d10830051", batch.Hash().Hex())

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x8c79c0bb0cb488864c97946fc3924abf603290cc423b88b7058f274d894e01fc", batch.Hash().Hex())

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x9b6b98a6e198c2f7b4ab6f40bf3cbd1ce40d68e54f120ff8e3c6bf22900486f3", batch.Hash().Hex())
}

func TestCodecV1BatchDataHash(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x9f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed541", batch.DataHash.Hex())

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xd46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a6", batch.DataHash.Hex())

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f", batch.DataHash.Hex())

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4", batch.DataHash.Hex())

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xc7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d", batch.DataHash.Hex())

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208", batch.DataHash.Hex())

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xe7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8", batch.DataHash.Hex())

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e134767", batch.DataHash.Hex())
}

func TestCodecV1BatchBlob(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded := strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "000000fd0600f40c0001000000e600f87180843b9aec2e8307a12094c0c4c8ba00ea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af68083019ecea0ab0007ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df51400a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf4002a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf039985866d800256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e8100065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f104006000b26207d8e42940b328b005", encoded)
	assert.Equal(t, "0x017b541197faa5cc281dc0ea3998955894598e6323f3219c3d1e4beaf4f65404", batch.BlobVersionedHash.Hex())

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "000018154f00a4600001000016310002f9162d82cf5502843b9b0a17831197e2008080b915d260806040523480156200001157600080fd5b50604051620014b200380380833981810160a08110378151602083015160408085018051915193950092948301929184640182116390830190602082018581798251811182820188001017945250918201929091019080838360005b83c3575183820152602001a900565b50905090811f16f15780820380516001836020036101000a03191681910050939291900115012b01460175015b01a35185519093508592508491c891600003918501906200026b8051de90600484506005805461ff001960ff199091160060121716905550600680546001a01b03808816199283161790925560078054009287169291909117905530815562b01633025062000307915050565b1660ff0092909282816001161502031660029000600020010481019282601f10ae57830080011785de0185558215575b82825182559190c1ec9291f090565b5b80815500f1565b61119b80176000396000f3fe61001004361061010b3560e01c80635c00975abb116100a257806395d89b4171146103019dc29fac09a457c2d735a905009cbb61dd62ed3e8d57565b029d70a08231a58456cb59cb8e50817ad3313ce50067de1d395093513b3f4ba83a6740c10f197106fdde0314610110095ea7b38d0018160dddcd23b872e7575b6101186103bb4020808252835181830191928392005261013a7f9280910390f3b960048036036040a381351690356104519115150082525190819003d561046e60fd81168101359091407402256104fbff4002510005046f610552565b0087610654d520bb3516610662067d56e9d20757031f0700b84b085f77c7d5a308db03601f600260001960018816150201909516949094000493840181028201925282609390830182820447578061041c578083540402008352565b8201915b81548152831161042a57821f160061046561045e61090600565b848461090a569202548184f604f18461048dec85606080602881108560002891398a166000905220906104cb819101549190610b93160511010522908100830193909320918c9252902054e80754331461059f5762461bcd60e51b6004000b60246a1b9bdd08185b1b1bddd95960aa1b60449064019005a7610c49565b009004156105f9106f14185d5cd8589b194e881c826006064606508282610ced00909006ca0ddd07260c6b6f6e6c7920466163746f72790792839182915516600004080808550e65086c251117602508968dd4832093909433831661094f040100808082810324806110f36024400191fd8294223d60228084819487168084520094829020859055815185815291517f8c5be1e5ebec7d5bd14f71427d1e84f300dd0314c0f7b2291e5b200ac8c7c3b92592a30a3b25ce0a80230ff86023610a008b838383610f6156c88126105f602686858082935590842054610af790828100558091937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f5005a4df523b3ef9203001115610be083818151910ba50b8d0bd2fd0c421b7f53006166654d6174683a206164646974696f6e206f766572666c6f7700610c9c140073627f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aea00e4b073aa610cd0a1560d481f7f45524332303a206d696e7420746f2074686500207a65726f72657373610d546000610d610255878393519293910e2d1762e7008cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a2580e00aa2110ad60210eb682f3221b8583550f190fb5826000919191610f6cb07415002a113c602a610c428383401e73756274726163815250fe6e73666572627572006e20616d6f75657863656564732062616c616e636561707072616c66726f6d006465637265617365642062655061757361626c656f6b656e7768696c652070006564a2646970667358221220e96342bec8f6c2bf72815a39998973b64c3bed0057770f402e9a7b7eeda0265d4c64736f6c634300060c0033001c5a77d9fa7e00f466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c001a000235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c63310072a02f7c0384ddd06970446e74229cd96216da62196dc62395bda52095d44b008a9af781e7a8b1448a18921111918224054907f10c41c841e8d203a28216c30048838c418610634464021121112948418a92c60461b80a6e15d6429e500acb007b35e8ca47c02a62e07f4d1e1d421f3ad0c0e181351fb3b9e94080467ead3200ed42f88c9f3cb8c456ebc6a129ffc7c2fa865c6c529073cab2ec381e1dc0160088db68705611cf2a78e3198f145b1113c8e23cd2ace7d822a710d73aebe41000b530680b30ca84ca6aec528f8171445351b992950bde6eba7dccf822f1fd5b00e0f05eb48534262f2b3225707eb4a238c3ebbd85470047234df3fb40522fca00258252817e1d40af6c1b4ed2212fccb6a004c8e1222fb44d8d5f4b06d3aa4000f0e4bb1ee37ff9cdad77eb0683854b265b62b82719bc2d1362c18f34ea6d80006f3e081008e33d7c04f2b9d21a1cfc707e09e05809d1d84a75534f44b3b26a00a82d28bc259257b249273e84cd6aa6b3aea01562e511597d66fa815a8019bb00eea82373de8046c0482b4199015e3fc310e662999865b4c3d252a2147dfc4600f127f5b5d38783befa99e7cbd3b76813f60722c66bf179e710c4111931b29c008ce5d3b4557131b2d904860e727b558e50830f150004605d1000b586f20ec1000cbdbb0f0b73ce7c7cb3dfbd7adfa3a57f92b026f973d736806ceb766a90ca00f04497a0c8602eb09e03709c672920b3fe820093d5742ef9a4794727bd9817006b76c3755f01f5aa4cad827eb2dbd7aed336966a3b9d22594c289270386b3e00de81b4660c4bf20820d45f6a38d3c4343c5d0a83bcecc14ec782bbc0cea4e9001d216237cadbf05508b8015ea31e1f3639500dfa8f25b0bac828061a4ba1a4000863f93c01d5acb66a9c3244936fac2cdec7f4ef305dceb46f8a7a9943f21100f075a9501d888be544ea9896e83276b1e645521f7dc8474f4dc89339cf0891003aa38d34bfaca0aab34642e691f6ec93c02515fdc8c5470aa86eda15daf458004b86995fff9e97caca386562e1478ebac8daa40ca48719509569421d34832800e633e7852e87ea20ce30ccb74ea4153ae50feaac52dfc46734045afd04a957009ba1ebc8966ff6dd0d9849e34520b7a76ef6997bccc2d7390ea67c0646303200b7634c4ca2ebbee881c66d797b4fc6cc9f0ba0e44df7c5549a3074df44fd5b00797b6edf6c67ab52b50a54ee8b2dbbc7a77cf4f643af3352198ded16b2dd6c00d535e7413b89b83d5f37990195c9a9a614e1784a9bfbc761bbe68cfa33d09100ef84f6c162b4c986cef73a60a4c9e6f8db93590f11fd5e862e2500d4f2e219007a56f5c33e68eaa83bea789d20467ef69a1e49ac705ac468ea57249e41b9920055f9921ac69a1ce7e81ee3d19222763a4a3f0574c0269df4c0ec38b03cf6cb005c9f2571aecd7855725d8ce309f8f19156f40ff792d51aa", encoded)
	assert.Equal(t, "0x01dc002f94d442ea74ddfd3a595f225f50861a5eb0ab6122db4916e30a251f25", batch.BlobVersionedHash.Hex())

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0000007d0100740200010000002000df0b80825dc0941a258d17bf244c4df02d0040343a7626a9d321e105808080808001002c0a1801", encoded)
	assert.Equal(t, "0x01416a70c569f7e638cc95d50c41c3e03eef3a487e83b1f2e1d8c2ca7b27e779", batch.BlobVersionedHash.Hex())

	// this batch only contains L1 txs
	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0000005d0000200001000001002f0a1001", encoded)
	assert.Equal(t, "0x015742f91b85b27644dcdc4177b705cdd5d6c8c1dd3c82ad77eda5623387da5a", batch.BlobVersionedHash.Hex())

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0000005d0000200001000001002f0a1001", encoded)
	assert.Equal(t, "0x015742f91b85b27644dcdc4177b705cdd5d6c8c1dd3c82ad77eda5623387da5a", batch.BlobVersionedHash.Hex())

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0000005d0000200001000001002f0a1001", encoded)
	assert.Equal(t, "0x015742f91b85b27644dcdc4177b705cdd5d6c8c1dd3c82ad77eda5623387da5a", batch.BlobVersionedHash.Hex())

	// 15 chunks
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0000102d0700e40c000f000000e6f87180843b9aec2e8307a12094c0c4c8baea003f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af68083019ecea0ab0700ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a00034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a008bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf039985866d825006f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e8106005f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f10600412400d3c68f60b26207d8e429402948979d170e", encoded)
	assert.Equal(t, "0x01da4f363bbc55e1635d83d2a66ff13ecb65a233ceef13941e718c5eb43e3248", batch.BlobVersionedHash.Hex())

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "000018a55600046f00020000173700f87180843b9aec2e8307a12094c0c4c8ba00ea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af68083019ecea0ab0007ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df51400a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf4002a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf039985866d800256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e8100065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f102f916002d82cf5502843b9b0a17831197e28080b915d26080604052348015620000110057600080fd5b50604051620014b2380380833981810160a0811037815160200083015160408085018051915193959294830192918464018211639083019060002082018581798251811182820188101794525091820192909101908083836000005b83c3575183820152602001a9565b50905090811f16f1578082038051600001836020036101000a031916819150939291900115012b01460175015b01a3005185519093508592508491c8916003918501906200026b8051de9060048450006005805461ff001960ff1990911660121716905550600680546001a01b03800088161992831617909255600780549287169291909117905530815562b0163300025062000307915050565b1660ff9290928281600116150203166002900060000020010481019282601f10ae578380011785de0185558215575b8282518255009190c1ec9291f090565b5b808155f1565b61119b80176000396000f3fe6100001004361061010b3560e01c80635c975abb116100a257806395d89b417114610003019dc29fac09a457c2d735a9059cbb61dd62ed3e8d57565b029d70a0823100a58456cb59cb8e50817ad3313ce567de1d395093513b3f4ba83a6740c10f19007106fdde0314610110095ea7b38d18160dddcd23b872e7575b6101186103bb0040208082528351818301919283925261013a7f9280910390f3b96004803603006040a3813516903561045191151582525190819003d561046e60fd8116810100359091407402256104fbff40025105046f610552565b0087610654d520bb350016610662067d56e9d20757031f07b84b085f77c7d5a308db03601f60026000001960018816150201909516949094049384018102820192528260939083018200820447578061041c5404028352565b8201915b81548152831161042a57821f00160061046561045e610906565b848461090a569202548184f604f18461048d00ec856060806028811085602891398a166000905220906104cb81910154919000610b931605110105229081168293909320918c9252902054e8075433146105009f5762461bcd60e51b60040b60246a1b9bdd08185b1b1bddd95960aa1b6044009064019005a7610c49565b9004156105f9106f14185d5cd8589b194e881c82006006064606508282610ced909006ca0ddd07260c6b6f6e6c7920466163746f00727907928391829155166004080808550e65086c251117602508968dd483200093909433831661094f0401808082810324806110f36024400191fd8294223d00602280848194871680845294829020859055815185815291517f8c5be1e5eb00ec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92592a30a3b0025ce0a80230ff86023610a8b838383610f6156c88126105f60268685808293005590842054610af7908281558091937fddf252ad1be2c89b69c2b068fc378d00aa952ba7f163c4a11628f55a4df523b3ef9203001115610be0838181518051000ba50b8d0bd2fd0c421b7f536166654d6174683a206164646974696f6e206f00766572666c6f7700610c9c1473627f5db9ee0a495bf2e6ff9c91a7834c1ba400fdd244a5e8aa4e537bd38aeae4b073aa610cd0a1560d481f7f45524332303a00206d696e7420746f20746865207a65726f72657373610d546000610d61025500878393519293910e2d1762e78cea01bee320cd4e420270b5ea74000d11b0c900f74754ebdbfc544b05a2580eaa2110ad60210eb682f3221b8583550f190fb500826000919191610f6cb074152a113c602a610c428383401e7375627472616300815250fe6e736665726275726e20616d6f75657863656564732062616c616e00636561707072616c66726f6d6465637265617365642062655061757361626c00656f6b656e7768696c6520706564a2646970667358221220e96342bec8f6c200bf72815a39998973b64c3bed57770f402e9a7b7eeda0265d4c64736f6c63430000060c0033001c5a77d9fa7ef466951b2f01f724bca3a5820b63a0e01209570045544820636f696e04c001a0235c1a8d40e8c347890397f1a92e6eadbd642200cf7c210e3e1737f0553c633172a02f7c0384ddd06970446e74229cd96216da0062196dc62395bda52095d44b8a9af7df0b80825dc0941a258d17bf244c4df0002d40343a7626a9d321e105808080808081eaa8013989981111111105490a920074010d41c841e7d203c28214c348a388418610634464021121515050901425008d010464000568d064c205a112d2687078e809595550a85f39390d7a0ba95700effb20881d3cb98143184566a132cdc2f8663561bcd0527977704a56bc3ca900e1f90cfce09cbcac308e99077889c49d293819ad9654f0f019278920fe09a400710a69967704242703833a7bec107531c0172065620545efd2f841068b9151009983b50b5e6ee4d2cca0380e93b740dbbd80010826312b8c920e6e34505c7600bd11d823309748d3fc16482a40b90c2639f2d74df5166dc3271d0ac26cfd2700a0391709c3bc49976a216a5ae90cfe6ba702fe97d1dc0a5bb7e12b5e32698900194cf2c2879970153f6ad423816f1e8b2900eafde758ffb9ca341d7f214f1c0076165ed0b752d9d453aa408d668b046fd39bd71bd27f0c61bf9a49d603b42400560090ee34d3b7a8859ab1ec8e6e32f00d18023644096210e07b330a61d6360037bf1166939652f8360fdf757fbea89d321cf4fedf5d7a3ccc2a4d374d6a91008959fc2be66cc28d8b74618d946102c1573130ea6642c69df9d6217eac6186009a2644ae8bdb50acb3bddbf98b77ed21da807c8f6fe49357effbb435cf12d6001c7fee5a03a8b76e430d062cadb604758539ae5d470f575eb0a063fdbd019d002ce95c48c7bc55ea24a3ee4b438570b54340e756a051a9a7ec42b732651edb00b04d4fef6f6c2c9270396be6deed62640cd3e2b994a880d4b89ed9a4f4342d0063f6328a1db02bf473b6ad695f770406f8b0090d267051bc7b3d8cb0295f33005c7e20c1f648d221e0592a922299a59e049c6635af7146201a75d7a4d11def007f24e3e499d64df19231239f84cfac02da81382c67571d63882e332eb2bc480020ce974ccb43487a32873ccc79ac8884186d50f48b2155786bd066e6cc9ed000108ead4fbfa3fe3c44830d5605103de8e4495394be17abb2989c12f1833650002f7dce5a0ee93900f464a7db581bc5135bc9f60a974354207e183e164f442b005021ead8d9ce3e93ef620800fd3192688d892e1996e9c8272160278d10e1cb009e6cb6c67b648faf711cdf7c162310993b1e3f4c7a749ff540e693a5b70446006f3ef52061ab9c85284e23619f4e27318446c5993bffaa5a6814d0b80b77e1006829e168660aa9cec86134b690d0695933c9a768ed1021a78b04b9017a03a0009a92e1f09476eebda7772131c46498230527408121d0dd0de5bf6dc0464d2e00c0d9feed1e49740930617a0fbcce8b64a852d50707a1a9a3ffbde33aed9a1400db73b8665b216fa1f8d355ce028ca112fa811735c4b5831b5a2363a99282e6001c9fd6cbe68809ba6f6069a44f8cbd0f8efa659c07d53da77e4b60fcc9e24300495a669403c24ae4a4d8a1ca83f9b35a4319", encoded)
	assert.Equal(t, "0x01795981f4ed52897102965ce76defc953c45835a947f4efe2957b0d29d476ae", batch.BlobVersionedHash.Hex())
}

func TestCodecV1BatchChallenge(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "4926034d144564bfb75a413a9245f2c92b3c53e7e4e6238e1ab1add1e8fc496a", hex.EncodeToString(batch.z[:]))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "359699931f78f368d790725692d655d0369b2dc64d316d18943e6c49808ce8f7", hex.EncodeToString(batch.z[:]))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "4f25448a3b40f945ae9c8b1e29d796bdeb148fc0449d8318fe62ce0a603a0125", hex.EncodeToString(batch.z[:]))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b", hex.EncodeToString(batch.z[:]))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b", hex.EncodeToString(batch.z[:]))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b", hex.EncodeToString(batch.z[:]))

	// 15 chunks
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "046a6437a6d1abc2cf39487c6fdb789d289817dbbca5a2a89d4d547e21cd30ac", hex.EncodeToString(batch.z[:]))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0abb7234091b0fcd8958d3b185cdf7e65ca8de8a66ee0da55d5abcf0ead10376", hex.EncodeToString(batch.z[:]))
}

func repeat(element byte, count int) string {
	result := make([]byte, 0, count)
	for i := 0; i < count; i++ {
		result = append(result, element)
	}
	return "0x" + common.Bytes2Hex(result)
}

func TestCodecV1BatchChallengeWithStandardTestCases(t *testing.T) {
	nRowsData := 126914

	for _, tc := range []struct {
		chunks    [][]string
		expectedz string
		expectedy string
	}{
		// single empty chunk
		{chunks: [][]string{{}}, expectedz: "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b", expectedy: "3ddf948c0ebcf3197032c78b20cbdab5e4c50da8e3e2a6db9af72caa399965e8"},
		// single non-empty chunk
		{chunks: [][]string{{"0x010203"}}, expectedz: "573706793982d45fb4be644b84e9b495adcc8b60fa49c348900c73772656c614", expectedy: "3f702cc1679ec556f99b1b67fa2226e57f9224c67e6a6b810c67dd080c30320f"},
		// multiple empty chunks
		{chunks: [][]string{{}, {}}, expectedz: "3f687e5fc7889c47dff95c34318fc8527bfa2b0a14e60779fc3b92fd0b57bfa0", expectedy: "0e9c56d3685b8201bff0a2192bc56f580eaecbeef91223fe87f21ec7ddce075a"},
		// multiple non-empty chunks
		{chunks: [][]string{{"0x010203"}, {"0x070809"}}, expectedz: "1a99a048c2f220e196ba36e43597aa753f9626370ce7c41fa28a06793edfba12", expectedy: "1dab34f11fb28059ac61d3299864f189503e4cbc2a64fccb945645a8f80d371f"},
		// empty chunk followed by non-empty chunk
		{chunks: [][]string{{}, {"0x010203"}}, expectedz: "43f5911941861a28ce16b162ea0884412cb4cc62fade3408e603e0c8751c55d3", expectedy: "5caa8b31ac0b99c461c065bb01023dd8e90b30f0ff52159e86098772d97f78c2"},
		// non-empty chunk followed by empty chunk
		{chunks: [][]string{{"0x070809"}, {}}, expectedz: "4ff23d805908d42eb5edd730ec951ad43eb2d656143d484351a202b244cdaa1c", expectedy: "6809153b21e5ed952d36cc909f9ebf259c2132db2b056fb9d7f8e1d3a9d7e97d"},
		// max number of chunks all empty
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}, expectedz: "247db6b02de743dee319df9466601bb65eab9437426b2ff74111e5bc1d2b98c2", expectedy: "6867fdb2a38bf2f0f22917532bd1e960c1a1c5e5a30ddc832078b94641ef3a66"},
		// max number of chunks all non-empty
		{chunks: [][]string{{"0x0a"}, {"0x0a0b"}, {"0x0a0b0c"}, {"0x0a0b0c0d"}, {"0x0a0b0c0d0e"}, {"0x0a0b0c0d0e0f"}, {"0x0a0b0c0d0e0f10"}, {"0x0a0b0c0d0e0f1011"}, {"0x0a0b0c0d0e0f101112"}, {"0x0a0b0c0d0e0f10111213"}, {"0x0a0b0c0d0e0f1011121314"}, {"0x0a0b0c0d0e0f101112131415"}, {"0x0a0b0c0d0e0f10111213141516"}, {"0x0a0b0c0d0e0f1011121314151617"}, {"0x0a0b0c0d0e0f101112131415161718"}}, expectedz: "000cf0d7a58fa8a2d586bdead94ce6f0b9a75394e9ca95f7d0a107a2938c2230", expectedy: "24032c3b009756df4bcada9a1e9170067a7e5604ad74c6cdded95b312a66d1dd"},
		// single chunk blob full
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "72534ab9ac158136191748e73312ed65cf8cefa14474249ee93c8780ed264d1c", expectedy: "036606531e4be50c4483518a7d85c180350f10f729f70a80d6383bc97628bf3d"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "12fe99dcf7582cd062d6b0195d59b26d9182500cbd8668e5733a8b5ace1b48da", expectedy: "254b01a087798ddefa3fabc0a8ddf30e4aed18122ee56f22f53e31c7b51a56b1"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "68f98d948123aae58067ca3c4efb791c9a340e0caf8cb1cab9370e15fe1aeb40", expectedy: "27ab10c4b0a0c12fc08a9f4b7984fdd4355ee259ada65627a8213bb3049ac7c1"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "28af25fddadb0696bbf219d7eec4428778db0856664486e3920235529e356949", expectedy: "5cd74ae14b44dfb1e14c28ff6ae322f0b714bfdc8ececfe7df56d9106cdaf252"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "2865e4aee81ad4ef2f22597dd64d63e7e7252b8bdc5aa177524ad2b276c8085c", expectedy: "4bf2f586963da4018a5ec23931243d73a0a4cfa7453c8297475c4c90814f8e81"},
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

		b, _, z, err := constructBlobPayload(chunks)
		assert.NoError(t, err)
		actualZ := hex.EncodeToString(z[:])
		assert.Equal(t, tc.expectedz, actualZ)

		_, y, err := kzg4844.ComputeProof(b, *z)
		assert.NoError(t, err)
		actualY := hex.EncodeToString(y[:])
		assert.Equal(t, tc.expectedy, actualY)

	}
}

func TestCodecV2BatchBlobDataProof(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err := batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "4926034d144564bfb75a413a9245f2c92b3c53e7e4e6238e1ab1add1e8fc496a59e6eb8f60294ef54e7c89e62a3037c1edc4b472c6fa742656f49487d52b5721a01d67f5fd21ff1d052085282b571e8bc2a5fdc4c6dca6551d6dc5da7fb485e41471c5757d834161f125487e6b6521f897b541bff40c65f83b1e03920f92700d40f78ce3b9ce09ebb8657ff8b1bcea37025fd96f1cb2f89a42fa95fcbdf69e08", hex.EncodeToString(verifyData))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "359699931f78f368d790725692d655d0369b2dc64d316d18943e6c49808ce8f71ad57c7ce96a9625a7e50d90a3e96a0ddb684ffc0e0485bb0056995fbff796898f50d15a73993841c91a7e0dd6bbd5932cd2c5b28970eb11e1dec424b38d9b9d95f26b7049cb49ac61b8dcbfefd54d8a9078e6f0fd14728f88b8d236d792a761cee5fe3eb3a332a606888b6d3e52cc713639de2163593baed755baffb1f88a74", hex.EncodeToString(verifyData))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "4f25448a3b40f945ae9c8b1e29d796bdeb148fc0449d8318fe62ce0a603a01250448cf808c41bfa835fe7f4f756feaaa8a5e9bef50489bd18e6d20859f7968baa620771de86a71d896a2281a6e6ac082079b8a55d9790128b9eb3983d21969e749231b39a35c6859d4dc41b2995c094e8985ed773b9976fd306cae440a2d5160950ec300a0eabccb011176d4c10a7e77b66bab6314373a2fd6f85e5b09f40d94", hex.EncodeToString(verifyData))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b3ddf948c0ebcf3197032c78b20cbdab5e4c50da8e3e2a6db9af72caa399965e8a1b72c34b090a407055e28efcae9a66373b3f354440e6ba168bace171faac4fa789a3cb93e783649e20ac76e79f62dc790ef813cda2f52df34b1e958f637840381a6d969507de2f018ee95e2fed9f59ac716dcc2123a0c0195c5fb25b55d52bf", hex.EncodeToString(verifyData))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b3ddf948c0ebcf3197032c78b20cbdab5e4c50da8e3e2a6db9af72caa399965e8a1b72c34b090a407055e28efcae9a66373b3f354440e6ba168bace171faac4fa789a3cb93e783649e20ac76e79f62dc790ef813cda2f52df34b1e958f637840381a6d969507de2f018ee95e2fed9f59ac716dcc2123a0c0195c5fb25b55d52bf", hex.EncodeToString(verifyData))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "0589f9d1a18d77bbabdf2c7abc3a37d0ed5dc0dffbef310ae0fa79a24167e90b3ddf948c0ebcf3197032c78b20cbdab5e4c50da8e3e2a6db9af72caa399965e8a1b72c34b090a407055e28efcae9a66373b3f354440e6ba168bace171faac4fa789a3cb93e783649e20ac76e79f62dc790ef813cda2f52df34b1e958f637840381a6d969507de2f018ee95e2fed9f59ac716dcc2123a0c0195c5fb25b55d52bf", hex.EncodeToString(verifyData))

	// 15 chunks
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "046a6437a6d1abc2cf39487c6fdb789d289817dbbca5a2a89d4d547e21cd30ac356accf6049f244e232a49ca5144d35e11f2ddcfc7a5cd742d528d53c0824d30ab83a10a200340f1332303b3e245c032a9a18c5ae3d3d7ce4bd5a4852c8018975497d9c9a0c8926fb03b2aa9cf690cc1945a92c24fd59380169a83f487bd9abf73d3ddf2151a97481c5be3d61f671252b0ac520afd521c8b847ba36e57f41e6d", hex.EncodeToString(verifyData))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProof()
	assert.NoError(t, err)
	assert.Equal(t, "0abb7234091b0fcd8958d3b185cdf7e65ca8de8a66ee0da55d5abcf0ead103762f6302533db813acc8a6eb935bf294519a231ef7394ac8748cf7e2d71cc38b2ba6f8f5e7269a81d459f9e9dbb6325a22b9f60fb552df59f8e42337f6436471c0aec58228cd6149f10d9fb46f6d9369b29721818659be1b9a2ce318d562d933f42ec44bc2fbad6eee9ed096fe4c84d5b33930d1785e0662600eb9f7354751cf1d", hex.EncodeToString(verifyData))
}

func TestCodecV2BatchSkipBitmap(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 0, int(batch.L1MessagePopped))
	assert.Equal(t, 0, int(batch.TotalL1MessagePopped))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 0, int(batch.L1MessagePopped))
	assert.Equal(t, 0, int(batch.TotalL1MessagePopped))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "00000000000000000000000000000000000000000000000000000000000003ff", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 11, int(batch.L1MessagePopped)) // skip 10, include 1
	assert.Equal(t, 11, int(batch.TotalL1MessagePopped))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000001fffffffff", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 42, int(batch.L1MessagePopped)) // skip 37, include 5
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 37
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 5, int(batch.L1MessagePopped)) // skip 37, include 5
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "00000000000000000000000000000000000000000000000000000000000001dd", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 10, int(batch.L1MessagePopped)) // skip 7, include 3
	assert.Equal(t, 10, int(batch.TotalL1MessagePopped))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 257, int(batch.L1MessagePopped)) // skip 255, include 2
	assert.Equal(t, 257, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 1
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 256, int(batch.L1MessagePopped)) // skip 254, include 2
	assert.Equal(t, 257, int(batch.TotalL1MessagePopped))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}} // queue index 10
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}                 // queue index 37-41
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000001ffffffbff", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 42, int(batch.L1MessagePopped))
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 10
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000007fffffe", hex.EncodeToString(batch.SkippedL1MessageBitmap))
	assert.Equal(t, 32, int(batch.L1MessagePopped))
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))
}

func TestCodecV2ChunkAndBatchBlobSizeEstimation(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	chunk2BlobSize, err := EstimateChunkL1CommitBlobSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(236), chunk2BlobSize)
	batch2 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch2BlobSize, err := EstimateBatchL1CommitBlobSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(236), batch2BlobSize)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	chunk3BlobSize, err := EstimateChunkL1CommitBlobSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2617), chunk3BlobSize)
	batch3 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch3BlobSize, err := EstimateBatchL1CommitBlobSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2617), batch3BlobSize)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk4BlobSize, err := EstimateChunkL1CommitBlobSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(54), chunk4BlobSize)
	batch4 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch4BlobSize, err := EstimateBatchL1CommitBlobSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(54), batch4BlobSize)

	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3}}
	chunk5BlobSize, err := EstimateChunkL1CommitBlobSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2834), chunk5BlobSize)
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk6BlobSize, err := EstimateChunkL1CommitBlobSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(54), chunk6BlobSize)
	batch5 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk5, chunk6}}
	batch5BlobSize, err := EstimateBatchL1CommitBlobSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2873), batch5BlobSize)
}

func readBlockFromJSON(t *testing.T, filename string) *encoding.Block {
	data, err := os.ReadFile(filename)
	assert.NoError(t, err)

	block := &encoding.Block{}
	assert.NoError(t, json.Unmarshal(data, block))
	return block
}
