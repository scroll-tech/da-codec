package codecv3

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
	"github.com/stretchr/testify/require"

	"github.com/scroll-tech/da-codec/encoding"
	"github.com/scroll-tech/da-codec/encoding/codecv0"
	"github.com/scroll-tech/da-codec/encoding/codecv2"
)

func TestCodecV3BlockEncode(t *testing.T) {
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

func TestCodecV3ChunkEncode(t *testing.T) {
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

func TestCodecV3ChunkHash(t *testing.T) {
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

func TestCodecV3BatchEncode(t *testing.T) {
	// empty batch
	batch := &DABatch{Version: uint8(encoding.CodecV3)}
	encoded := hex.EncodeToString(batch.Encode())
	assert.Equal(t, "03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "030000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101bbc6b98d7d3783730b6208afac839ad37dcf211b9d9e7c83a5f9d02125ddd700000000000000000000000000000000000000000000000000000000000000000000000063807b2a098f1f136f5734039818bee35222d35a96acd7d17120ce8816307527d19badea17d013be5ef696cfbc05b97bb322a587432c2cb23c4848d4d7cb8453c475b38d", encoded)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "03000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a601fae670a781fb1ea366dad9c02caf4ea1de4f699214c8171f9219b0c72f6ad400000000000000000000000000000000000000000000000000000000000000000000000063807b2d2c440817c5d20c385554774de3fa5d9f32da1dcba228e5cf04f627a41b4b779203f4ef0f3161a3a812523673119d90fb5303248b9fc58c3031a7f4b0937912b8", encoded)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "030000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f012e15203534ae3f4cbe1b0f58fe6db6e5c29432115a8ece6ef5550bf2ffce4c000000000000000000000000000000000000000000000000000000000000000000000000646b6e133e935190ba34184cc7bf61a54e030b0ec229292b3025c14c3ef7672b259521cf27c007dc51295c1fe2e05882128a62ef03fb30aaaa4415505929eac7f35424f2", encoded)

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "030000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000646b6ed030ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", encoded)

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "030000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000646b6ed030ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", encoded)

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "03000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000646b6ed030ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", encoded)

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "030000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8013750f6cb783ce2e8fec5a8aff6c45512f2496d6861204b11b6010fb4aa0029000000000000000000000000000000000000000000000000000000000000000000000000646b6ed073c21fcf521e068860a235a4b8f2cdf4a67966ccee1bb46b804b1e7d85333b516c079a4f68903dd18292f1bbdb36b2c94fcefe676931073c2340b2545a504de4", encoded)

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(batch.Encode())
	assert.Equal(t, "030000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e1347670128f90d5edbcb10d13521824ccc7f47f85aff6e2da01004f9a402854eb33632000000000000000000000000000000000000000000000000000000000000000000000000646b6ed01bea70cbdd3d088c0db7d3dd5a11a2934ec4e7db761195d1e62f9f38a2fd5b325910eea5d881106c394f8d9a80bac8ecc43a86e0b920c5dc93f89caa43b205c2", encoded)
}

func TestCodecV3BatchHash(t *testing.T) {
	// empty batch
	batch := &DABatch{Version: uint8(encoding.CodecV3)}
	assert.Equal(t, "0x9f059299e02cd1ccaed5bbcc821843000ae6b992b68b55ff59a51252478681b0", batch.Hash().Hex())

	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xc5065afb8f29f620ae1edb4c6ebaf7380faf4226fb83ee920d70d489fe51c5c2", batch.Hash().Hex())

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x9ec8eabaa13229ec9c9d0687133afd7435afcfe260fc4c73fea052c0911522ac", batch.Hash().Hex())

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xda944b66dcaa6dc1442be2230233e97286ee1ed3c51cde155a36643b293b07c4", batch.Hash().Hex())

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x20e2324fac82e484c569eb286a221c61151c2b3c38a63b289f6ef6c30fb31e49", batch.Hash().Hex())

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xc962bce28a34a4eb9ec81393edcf2e6367e84aad9c4fc5641da6f18f54053ed5", batch.Hash().Hex())

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x405e0fc4b7efbe5b6d1dcc63c1f3253bbb6fbefedd1afe6b2067629f9da1f1cc", batch.Hash().Hex())

	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk3, chunk4, chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0x3d5d24c951cb55e56f3b4e2defcd8f32d6d048565e6723ac7cdff7ed5e580e3a", batch.Hash().Hex())

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "0xb25d9bd7d8442a56efd8e5ee814a99da7efdf3672bb85c48b975a9e248711bfb", batch.Hash().Hex())
}

func TestCodecV3BatchDataHash(t *testing.T) {
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

func TestCodecV3BatchBlob(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded := strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "00609c00fd0600240d0001000000e600f87180843b9aec2e8307a12094c0c4c800baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808301009ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a4100e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec00288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03900985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a0005a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed3200f1030060b26d07d8b028b005", encoded)
	assert.Equal(t, "0x01bbc6b98d7d3783730b6208afac839ad37dcf211b9d9e7c83a5f9d02125ddd7", batch.BlobVersionedHash.Hex())

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0060e7159d580094830001000016310002f9162d82cf5502843b9b0a1783119700e28080b915d260806040523480156200001157600080fd5b5060405162001400b2380380833981810160405260a0811037815160208301516040808501805100915193959294830192918464018211639083019060208201858179825181110082820188101794825250918201929091019080838360005b83c357818101510083820152602001620000a9565b50505050905090810190601f16f1578082030080516001836020036101000a0319168191508051604051939291900115012b0001460175015b01a39081015185519093508592508491620001c891600391850001906200026b565b508051620001de90600490602084506005805461ff00190060ff1990911660121716905550600680546001600160a01b0380881619928300161790925560078054928716929091169190911790556200023081620002550062010000600160b01b03191633021790555062000307915050565b60ff19160060ff929092565b828160011615610100020316600290049060005260206000002090601f016020900481019282601f10620002ae5780518380011785de016000010185558215620002de579182015b8202de5782518255916020019190600100c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000002f1565b61119b80620003176000396000f3fe61001004361061010b576000003560e01c80635c975abb116100a257806395d89b411161007114610301578000639dc29fac14610309578063a457c2d714610335578063a9059cbb1461036100578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114610200a55780638456cb59146102cb5780638e50817a146102d3313ce567116100de00571461021d578063395093511461023b5780633f4ba83a146102675780634000c10f191461027106fdde0314610110578063095ea7b31461018d5780631816000ddd146101cd57806323b872e7575b6101186103bb565b6040805160208082005283518183015283519192839290830161015261013a61017f9250508091030090f35b6101b9600480360360408110156101a381351690602001356104519100151582525190819003602001d561046e60fd81169160208101359091169060004074565b6102256104fb60ff90921640025105046f610552565b005b61026f00028705a956610654d520bb3516610662067d56e90135166106d21861075703001f07b856034b085f77c7d5a308db565b6003805420601f600260001961010000600188161502019095169490940493840181900481028201810190925282810052606093909290918301828280156104475780601f1061041c57610100808300540402835291610447565b825b8154815260200180831161042a5782900360001f16820191565b600061046561045e610906565b848461090a565b506001920002548184f6565b6104f18461048d6104ec8560405180606080602861108560002891398a166000908152600160205260408120906104cb81019190915260400001600020549190610b51565b935460ff160511016000610522908116825260002080830193909352604091820120918c168152925290205490610be8565b60000716331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b1b001bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090040060ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606460006508282610ced909052604006ca0ddd900407260c6b6f6e6c792046616374006f727960a0079283918216179091559390921660041561080808550e65086c002511176025006108968dd491824080832093909416825233831661094f5704000180806020018281038252602401806110f36024913960400191fd821661090094223d60228084166000819487168084529482529182902085905581518581005291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200a00c8c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a8b00838383610f61565b610ac881265f60268685808220939093559084168152200054610af7908220409490945580905191937fddf252ad1be2c89b69c2b068fc00378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484111561000be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53610066654d6174683a206164646974696f6e206f766572666c6f7700610c9c147300621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd3008aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e7420746f0020746865207a65726f72657373610d546000600254610d610255902054610d008780838393519293910e2d6101001790557f62e78cea01bee320cd4e42027000b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad6021610e00b68260000ef3221b85839020550f199082610fb540805182600091851691910020565b610f6cb07415610fb02a113c602a00610c428383401e7375627472610063815250fe7472616e736665726275726e20616d6f756e742065786365656400732062616c616e6365617070726f7665616c6c6f7766726f6d646563726561007365642062656c6f775061757361626c653a20746f6b656e7768696c652070006175736564a2646970667358221220e96342bec8f6c2bf72815a39998973b6004c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a77d900fa7ef466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c00001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c00633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda5209500d44b8a9af7813ca8c134a9149a111111110549d2740105c410e61ca4d60312006013290b6398528818e2c8484081888c4890142465a631e63178f9940048f4006ba77adb9be01e898bbbfbc0afba2b64ed71162098740e35ec699633c6a84900670da2d948458ecd9f2e5dc5c5ac4afe3d62cf457cd3507b2eae71e064fab30088531f9c708fd40558dfc698511c4a68234d058c4972da28f0201c4ee550b500e36f0bb42e46bb556d6197be7ea27a3a853e5da024de5ea930350219b1638a00a1dcd41f8222f5d647291e05238c248aa4e028278ad4a9a720f5c16f637166004c4cc255e402cdf64c88e9231dd28a07b8f0ddf1dd7b388875a13dc6d447c000318bca02c54cdfa3621635af1ff932928dfde06038ac9729c301f9f3a3a395008d502ba9e137cc24c14cb4102cf6ba6708b9c812c3ba59a3cbcc5d2aafa8b50097b49fbeb704a22b6137ae9a13b600ad73748768b42756ba338f9854164b1b003f3e23255e4db853a2d3276f061093a37810212ba36db205219fab403242800009178588ad21f754085dd807b09af69e6f06bccbcef8ade3b1f0eb15a077b8005b024ecef4087f261a0d4033355c1e544bd0b0c100276008c420d6d30bc8be00a3ba741063e8b48cf152d3695c0904d477318d4ad46477cdf962443336479f00bd86fd52d4e2a1d23eeddc52463d524b44644abdcd097025bcf9cc636fc1030092cb15b81d7ea667f3ba711624bbf04e992871a6ea4f9d367ba6d46142176f00cdf03e4e19549d2eea45ca804421f6bc33933aab6d478b291bf3619fe15bc900975409d8f3677a87d1b1f7acdb3071b752f3d95c9363ac9c83752f223e45e50079308f554787b4d1f74e389823923f5d268be545466a2dd449963ad25407bd003a18601410b91ca081537f67ea8d527a49adf256f2363346ea35a2fe2768a900091a184f59680df81982c6087efc651f54693a7870aa7c13dcf054c39536c500de8a2dd66955567ff1730dac8533de482aed706ed3417823dd65d058b98899008d54917fd1f70735f7a6a8b1a053c08aac96fb04", encoded)
	assert.Equal(t, "0x01fae670a781fb1ea366dad9c02caf4ea1de4f699214c8171f9219b0c72f6ad4", batch.BlobVersionedHash.Hex())

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0020d67d0100740200010000002000df0b80825dc0941a258d17bf244c4df02d0040343a7626a9d321e105808080808001002c0a1801", encoded)
	assert.Equal(t, "0x012e15203534ae3f4cbe1b0f58fe6db6e5c29432115a8ece6ef5550bf2ffce4c", batch.BlobVersionedHash.Hex())

	// this batch only contains L1 txs
	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0020b6550000180001000100300a0c01", encoded)
	assert.Equal(t, "0x015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370", batch.BlobVersionedHash.Hex())

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0020b6550000180001000100300a0c01", encoded)
	assert.Equal(t, "0x015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370", batch.BlobVersionedHash.Hex())

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0020b6550000180001000100300a0c01", encoded)
	assert.Equal(t, "0x015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370", batch.BlobVersionedHash.Hex())

	// 15 chunks
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0060300d2d0700140d000f000000e6f87180843b9aec2e8307a12094c0c4c8ba00ea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019e00cea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e8006df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec28008bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03998005866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a003e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f10005004124d3c68f60b26d07d824482d965c11", encoded)
	assert.Equal(t, "0x0140a7ef703ef625ee71e6a580a8ff05cab32c3f3402bd37a1b715f5810760c9", batch.BlobVersionedHash.Hex())

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.blob[:]), "0")
	assert.Equal(t, "0060ed16256000449200020000173700f87180843b9aec2e8307a12094c0c4c800baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808301009ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a4100e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec00288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03900985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a0005a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed3200f102f9162d82cf5502843b9b0a17831197e28080b915d26080604052348015006200001157600080fd5b50604051620014b2380380833981810160405260a000811037815160208301516040808501805191519395929483019291846401820011639083019060208201858179825181118282018810179482525091820192009091019080838360005b83c3578181015183820152602001620000a9565b5000505050905090810190601f16f15780820380516001836020036101000a031900168191508051604051939291900115012b01460175015b01a3908101518551009093508592508491620001c8916003918501906200026b565b50805162000100de90600490602084506005805461ff001960ff199091166012171690555060000680546001600160a01b03808816199283161790925560078054928716929000911691909117905562000230816200025562010000600160b01b0319163302001790555062000307915050565b60ff191660ff929092565b828160011615610001000203166002900490600052602060002090601f01602090048101928260001f10620002ae5780518380011785de0160010185558215620002de57918201005b8202de57825182559160200191906001c1565b50620002ec9291f0565b500090565b5b8002ec5760008155600101620002f1565b61119b8062000317600000396000f3fe61001004361061010b5760003560e01c80635c975abb116100a20057806395d89b4111610071146103015780639dc29fac14610309578063a45700c2d714610335578063a9059cbb14610361578063dd62ed3e1461038d576101000b565b1461029d57806370a08231146102a55780638456cb59146102cb578000638e50817a146102d3313ce567116100de571461021d57806339509351146100023b5780633f4ba83a1461026757806340c10f191461027106fdde031461010010578063095ea7b31461018d57806318160ddd146101cd57806323b872e757005b6101186103bb565b6040805160208082528351818301528351919283929000830161015261013a61017f92505080910390f35b6101b960048036036040810010156101a3813516906020013561045191151582525190819003602001d56100046e60fd811691602081013590911690604074565b6102256104fb60ff9092001640025105046f610552565b005b61026f028705a956610654d520bb351661000662067d56e90135166106d218610757031f07b856034b085f77c7d5a308db00565b6003805420601f600260001961010060018816150201909516949094040093840181900481028201810190925282815260609390929091830182828015006104475780601f1061041c576101008083540402835291610447565b825b810054815260200180831161042a57829003601f16820191565b60006104656104005e610906565b848461090a565b5060019202548184f6565b6104f18461048d006104ec85604051806060806028611085602891398a16600090815260016020005260408120906104cb810191909152604001600020549190610b51565b93540060ff160511016000610522908116825260208083019390935260409182012000918c168152925290205490610be8565b600716331461059f5762461bcd60e5001b60040b60248201526a1b9bdd08185b1b1bddd95960aa1b60448201529064000190fd5b6105a7610c49565b610100900460ff16156105f9106f14185d5cd800589b194e881c185d5cd95960826006064606508282610ced909052604006ca000ddd900407260c6b6f6e6c7920466163746f727960a007928391821617909100559390921660041561080808550e65086c2511176025006108968dd49182400080832093909416825233831661094f5704018080602001828103825260240100806110f36024913960400191fd8216610994223d60228084166000819487160080845294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f0071427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92592819003a350831661000a3b25ce8216610a80230ff86023610a8b838383610f61565b610ac881265f00602686858082209390935590841681522054610af790822040949094558090005191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a004df523b3ef9291829003008184841115610be08381815191508051900ba50b008d0bd2fd900300828201610c421b7f536166654d6174683a20616464697469006f6e206f766572666c6f7700610c9c1473621690557f5db9ee0a495bf2e6ff009c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa610cd0a18216610d00481f7f45524332303a206d696e7420746f20746865207a65726f7265737361000d546000600254610d610255902054610d8780838393519293910e2d610100001790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc00544b05a2588216610eaa6021ad6021610eb68260000ef3221b85839020550f00199082610fb5408051826000918516919120565b610f6cb07415610fb02a11003c602a00610c428383401e73756274726163815250fe7472616e73666572620075726e20616d6f756e7420657863656564732062616c616e6365617070726f007665616c6c6f7766726f6d6465637265617365642062656c6f77506175736100626c653a20746f6b656e7768696c6520706175736564a264697066735822120020e96342bec8f6c2bf72815a39998973b64c3bed57770f402e9a7b7eeda026005d4c64736f6c634300060c00331c5a77d9fa7ef466951b2f01f724bca3a582000b63a0e012095745544820636f696e04c001a0235c1a8d40e8c347890397f100a92e6eadbd6422cf7c210e3e1737f0553c633172a02f7c0384ddd06970446e0074229cd96216da62196dc62395bda52095d44b8a9af7df0b80825dc0941a25008d17bf244c4df02d40343a7626a9d321e1058080808080813ea8c134a9149a00111111110549d2740105c410e61ca4d603126013290b6398528818e2c848400081888c4890142465a631e63178f9940048f46ba77adb9be01e898bbbfb80cc00ba2b64ed71162098740e35ec699633c6a849670da2d948458ecd9f2e5dc5c500ac4afe3d62cf457cd3507b2eae71e064fab388531f9c708fd40558dfc69851001c4a68234d058c4972da28f0201c4ee550b5e36f0bb42e46bb556d6197be7e00a27a3a853e5da024de5ea930350219b1638aa1dcd41f8222f5d647291e0523008c248aa4e028278ad4a9a720f5c16f6371664c4cc255e402cdf64c88e9231d00d28a07b8f0ddf1dd7b388875a13dc6d447c0318bca02c54cdfa3621635af1f00f932928dfde06038ac9729c301f9f3a3a3958d502ba9e137cc24c14cb4102c00f6ba6708b9c812c3ba59a3cbcc5d2aafa8b597b49fbeb704a22b6137ae9a1300b600ad73748768b42756ba338f9854164b1b3f3e23255e4db853a2d3276f06001093a37810212ba36db205219fab4032428009178588ad21f754085dd807b0009af69e6f06bccbcef8ade3b1f0eb15a077b85b024ecef4087f261a0d403335005c1e544bd0b0c100276008c420d6d30bc8bea3ba741063e8b48cf152d3695c000904d477318d4ad46477cdf962443336479fbd86fd52d4e2a1d23eeddc5246003d524b44644abdcd097025bcf9cc636fc10392cb15b81d7ea667f3ba71162400bbf04e992871a6ea4f9d367ba6d46142176fcdf03e4e19549d2eea45ca80440021f6bc33933aab6d478b291bf3619fe15bc9975409d8f3677a87d1b1f7acdb003071b752f3d95c9363ac9c83752f223e45e579308f554787b4d1f74e38982300923f5d268be545466a2dd449963ad25407bd3a18601410b91ca081537f67ea008d527a49adf256f2363346ea35a2fe2768a9091a184f59680df81982c6087e00fc651f54693a7870aa7c13dcf054c39536c5de8a2dd66955567ff1730dac850033de482aed706ed3417823dd65d058b988998d54917fe9bb80f5ee4d5c636d00a70ee60a586fdb282babf53e01", encoded)
	assert.Equal(t, "0x0128f90d5edbcb10d13521824ccc7f47f85aff6e2da01004f9a402854eb33632", batch.BlobVersionedHash.Hex())
}

func TestCodecV3BatchChallenge(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "098f1f136f5734039818bee35222d35a96acd7d17120ce8816307527d19badea", hex.EncodeToString(batch.z[:]))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "2c440817c5d20c385554774de3fa5d9f32da1dcba228e5cf04f627a41b4b7792", hex.EncodeToString(batch.z[:]))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "3e935190ba34184cc7bf61a54e030b0ec229292b3025c14c3ef7672b259521cf", hex.EncodeToString(batch.z[:]))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e", hex.EncodeToString(batch.z[:]))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e", hex.EncodeToString(batch.z[:]))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e", hex.EncodeToString(batch.z[:]))

	// 15 chunks
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "1bc420092ec4e0af62e7a9243dd6a39ee1341e33032647d3edc16fb4dea5f60a", hex.EncodeToString(batch.z[:]))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, "1bea70cbdd3d088c0db7d3dd5a11a2934ec4e7db761195d1e62f9f38a2fd5b32", hex.EncodeToString(batch.z[:]))
}

func TestCodecV3ChunkAndBatchCommitGasEstimation(t *testing.T) {
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

func TestCodecV3BatchChallengeWithStandardTestCases(t *testing.T) {
	nRowsData := 126914

	for _, tc := range []struct {
		chunks    [][]string
		expectedz string
		expectedy string
	}{
		// single empty chunk
		{chunks: [][]string{{}}, expectedz: "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e", expectedy: "132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2"},
		// single non-empty chunk
		{chunks: [][]string{{"0x010203"}}, expectedz: "13c58784e6eeed40130ab43baa13a1f2d5a6d895c66f554456e00c480568a42d", expectedy: "248ace7f7f0fb3718b80b8cf04be560b97d083a3dbbd79d169e0fe9c80c9668c"},
		// multiple empty chunks
		{chunks: [][]string{{}, {}}, expectedz: "102e7bf1335a8a86e8ecac2283843eff536555e464bb6ba01a29ff1ca8d4b8cb", expectedy: "033a0272284ae81eb693588e731fc19ad24c44a332405e471966335b37f1a2c2"},
		// multiple non-empty chunks
		{chunks: [][]string{{"0x010203"}, {"0x070809"}}, expectedz: "0ac462d144c9aa1a7538aebd9087e34e9f9590e59b58ffa08f03cd9e43382ed0", expectedy: "6ac7fc7686c900c9e27fd0ca69736cf77016c8b9e8fd3ebab0ee6be1d6c30c93"},
		// empty chunk followed by non-empty chunk
		{chunks: [][]string{{}, {"0x010203"}}, expectedz: "1d81a4d2c78fbbf379562a998edde942b2019ec88ede9150a4c2a52a4e271ace", expectedy: "656603441f898b3dd64e0963fea53bfd6a445cb4f838c5caf181186cf45dd7ec"},
		// non-empty chunk followed by empty chunk
		{chunks: [][]string{{"0x070809"}, {}}, expectedz: "275116a8ff16b17b90d7287fb567e766d1f79f54f8ac3c6d80e2de59fd34f115", expectedy: "5fea2c1bbed12ccdcf9edef780330ee1d13439de4d3b8f4968f2bda9e4fb8b1f"},
		// max number of chunks all empty
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}, expectedz: "33b08755ea887e280006095461a7d59e510499dde813da272a319917dfa4505b", expectedy: "5c16121084471119ebcd8b87d38c4ebf64de00e29da67dbf2238a5cf1173b2ca"},
		// max number of chunks all non-empty
		{chunks: [][]string{{"0x0a"}, {"0x0a0b"}, {"0x0a0b0c"}, {"0x0a0b0c0d"}, {"0x0a0b0c0d0e"}, {"0x0a0b0c0d0e0f"}, {"0x0a0b0c0d0e0f10"}, {"0x0a0b0c0d0e0f1011"}, {"0x0a0b0c0d0e0f101112"}, {"0x0a0b0c0d0e0f10111213"}, {"0x0a0b0c0d0e0f1011121314"}, {"0x0a0b0c0d0e0f101112131415"}, {"0x0a0b0c0d0e0f10111213141516"}, {"0x0a0b0c0d0e0f1011121314151617"}, {"0x0a0b0c0d0e0f101112131415161718"}}, expectedz: "0e1b72e4466f0c7eeb037cbd3d2e331064f04918761d6f93ca77df420f9b2eaf", expectedy: "05fe38cd1b145264bf73bc56d5a8845036fb3de2a47d4f4aa4169fc200c2eaa0"},
		// single chunk blob full
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "27fa11d85fe287c8a6856eb9e5c5beda434d1fe2546acdba2b8dfa2ba7ab1d88", expectedy: "3779e3107e53b9bf8f2c321555c8b11794658697ad3331d554c4f9349da54c10"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "1043772b5108fdab00a783973907e894f49b2a2f9161fc40e1cac49c11b440f6", expectedy: "26252617e2f2082d644d2cace2b952f2fcc2eadee7ad53bdc318a4b8eb6687f3"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "5be7c98e72cba00fa2d2db53ea0aae8ed51d69cbd5a8ee3f1c9090eaa9b4069d", expectedy: "3741b74e012b1196cc20efe0274914037a87957b0580408568783071f2b7fb73"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "2685529f135d0657d77a70ce21e1ae5edb5c6a822f85fd4b8881361ef79b1aca", expectedy: "64c4b81ac600ba7699050bf6f705c60974bc3f48193fe0506f95572062fa3d36"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "2ce5c98ca63d933e2cddd9a17d47dbf9e457d66cc2c531a56d7a6c820bb8b200", expectedy: "44990a2427f91f2db69be6ac7a36ecaac9074ed17b1040bad9cbfeffcd68cbf1"},
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

		b, _, z, err := codecv2.ConstructBlobPayload(chunks, true /* use mock */)
		assert.NoError(t, err)
		actualZ := hex.EncodeToString(z[:])
		assert.Equal(t, tc.expectedz, actualZ)

		_, y, err := kzg4844.ComputeProof(b, *z)
		assert.NoError(t, err)
		actualY := hex.EncodeToString(y[:])
		assert.Equal(t, tc.expectedy, actualY)

	}
}

func TestCodecV3BatchBlobDataProof(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err := batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "098f1f136f5734039818bee35222d35a96acd7d17120ce8816307527d19badea17d013be5ef696cfbc05b97bb322a587432c2cb23c4848d4d7cb8453c475b38d90b7a581ba5b2cd6a916d139d2b7f28bf6997adb512653f6bdef0bbb7d681c742560fab406fd299c04fc1a464d277f8a8b3a918761888bd0f9a96cb9b2521347131a43b633c4fa01470842d9fe4211bc59c990f69185b80def79b9dfbf039b75", hex.EncodeToString(verifyData))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "2c440817c5d20c385554774de3fa5d9f32da1dcba228e5cf04f627a41b4b779203f4ef0f3161a3a812523673119d90fb5303248b9fc58c3031a7f4b0937912b8b1530a433168a29443af928876b3d63f4205ba1876d303d56f8456483b9ce91b6ff2b1707726f01c1429cb9d87e4c165ade0ec9e0547ea5721ff442f63d8fcf9ba2f066b07d9b8a0f057e9c0e0e1e56f9a6ec627f9b1cb24866802e15c49c22a", hex.EncodeToString(verifyData))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "3e935190ba34184cc7bf61a54e030b0ec229292b3025c14c3ef7672b259521cf27c007dc51295c1fe2e05882128a62ef03fb30aaaa4415505929eac7f35424f2a5979717c35155300b0b2d68610aacdd8b0dbb94990168103bfd62985732e3f682370c91c9f2b8f08c6398194e2bb18b83eae765cef6e4e991d91e631dd454953516721962a089a03e4d8f640cd115ede836bad7141e8094317a45ccd04ec842", hex.EncodeToString(verifyData))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2aa4fe1ee5d7af73b27b10c68f66f4c3700ffe684aa0593cd19690e8075303ca7d395e6d0add8aa5e3e668820713c3377a8bf6769fc8bef4d141ac117962ae0fc2e2606862b3542e5e9b6197f9dcd8a4b126a08b160da6ade484dd4cc1c7be4be", hex.EncodeToString(verifyData))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2aa4fe1ee5d7af73b27b10c68f66f4c3700ffe684aa0593cd19690e8075303ca7d395e6d0add8aa5e3e668820713c3377a8bf6769fc8bef4d141ac117962ae0fc2e2606862b3542e5e9b6197f9dcd8a4b126a08b160da6ade484dd4cc1c7be4be", hex.EncodeToString(verifyData))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2aa4fe1ee5d7af73b27b10c68f66f4c3700ffe684aa0593cd19690e8075303ca7d395e6d0add8aa5e3e668820713c3377a8bf6769fc8bef4d141ac117962ae0fc2e2606862b3542e5e9b6197f9dcd8a4b126a08b160da6ade484dd4cc1c7be4be", hex.EncodeToString(verifyData))

	// 15 chunks
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "1bc420092ec4e0af62e7a9243dd6a39ee1341e33032647d3edc16fb4dea5f60a0fad18d05f6f7d57b03dc717f8409489806d89ee5044bea951538682c52d815097e898dbd9a99b1bae2d759ee5f77ac6b6e8fb2cddaf26500532270fd4066e7ae85c450bcbf2cdb4643147091a1ee11ca615b823c97a69cb716d80de6ccafc5823af3a17fc71b72c224edd387abbf4433af013b53f15f394e501e5a3e57af074", hex.EncodeToString(verifyData))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}}
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = batch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "1bea70cbdd3d088c0db7d3dd5a11a2934ec4e7db761195d1e62f9f38a2fd5b325910eea5d881106c394f8d9a80bac8ecc43a86e0b920c5dc93f89caa43b205c2880cc02297edda15b6a14c4481fd15db8209aa52b80aecde6fce0592093eaf0d813c2f081eacb1efa9a8030191e1b780b421b0df42cc64da5e466af6f8cbc20afcb993e6d217440b5b21f2be91abe8620e1518780aa2005ec0a80cb947ebfef9", hex.EncodeToString(verifyData))
}

func TestCodecV3BatchL1MessagePopped(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	originalBatch := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch, err := NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 0, int(batch.L1MessagePopped))
	assert.Equal(t, 0, int(batch.TotalL1MessagePopped))

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 0, int(batch.L1MessagePopped))
	assert.Equal(t, 0, int(batch.TotalL1MessagePopped))

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 11, int(batch.L1MessagePopped)) // skip 10, include 1
	assert.Equal(t, 11, int(batch.TotalL1MessagePopped))

	trace5 := readBlockFromJSON(t, "../testdata/blockTrace_05.json")
	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk5}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 42, int(batch.L1MessagePopped)) // skip 37, include 5
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 37
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 5, int(batch.L1MessagePopped)) // skip 37, include 5
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	trace6 := readBlockFromJSON(t, "../testdata/blockTrace_06.json")
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace6}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk6}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 10, int(batch.L1MessagePopped)) // skip 7, include 3
	assert.Equal(t, 10, int(batch.TotalL1MessagePopped))

	trace7 := readBlockFromJSON(t, "../testdata/blockTrace_07.json")
	chunk7 := &encoding.Chunk{Blocks: []*encoding.Block{trace7}}
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk7}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 257, int(batch.L1MessagePopped)) // skip 255, include 2
	assert.Equal(t, 257, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 1
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 256, int(batch.L1MessagePopped)) // skip 254, include 2
	assert.Equal(t, 257, int(batch.TotalL1MessagePopped))

	chunk8 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3, trace4}} // queue index 10
	chunk9 := &encoding.Chunk{Blocks: []*encoding.Block{trace5}}                 // queue index 37-41
	originalBatch = &encoding.Batch{Chunks: []*encoding.Chunk{chunk8, chunk9}}
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 42, int(batch.L1MessagePopped))
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))

	originalBatch.TotalL1MessagePoppedBefore = 10
	batch, err = NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, 32, int(batch.L1MessagePopped))
	assert.Equal(t, 42, int(batch.TotalL1MessagePopped))
}

func TestCodecV3ChunkAndBatchBlobSizeEstimation(t *testing.T) {
	trace2 := readBlockFromJSON(t, "../testdata/blockTrace_02.json")
	chunk2 := &encoding.Chunk{Blocks: []*encoding.Block{trace2}}
	chunk2BatchBytesSize, chunk2BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), chunk2BatchBytesSize)
	assert.Equal(t, uint64(237), chunk2BlobSize)
	batch2 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk2}}
	batch2BatchBytesSize, batch2BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), batch2BatchBytesSize)
	assert.Equal(t, uint64(237), batch2BlobSize)

	trace3 := readBlockFromJSON(t, "../testdata/blockTrace_03.json")
	chunk3 := &encoding.Chunk{Blocks: []*encoding.Block{trace3}}
	chunk3BatchBytesSize, chunk3BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), chunk3BatchBytesSize)
	assert.Equal(t, uint64(2933), chunk3BlobSize)
	batch3 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk3}}
	batch3BatchBytesSize, batch3BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), batch3BatchBytesSize)
	assert.Equal(t, uint64(2933), batch3BlobSize)

	trace4 := readBlockFromJSON(t, "../testdata/blockTrace_04.json")
	chunk4 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk4BatchBytesSize, chunk4BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk4BatchBytesSize)
	assert.Equal(t, uint64(54), chunk4BlobSize)
	batch4 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk4}}
	blob4BatchBytesSize, batch4BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), blob4BatchBytesSize)
	assert.Equal(t, uint64(54), batch4BlobSize)

	chunk5 := &encoding.Chunk{Blocks: []*encoding.Block{trace2, trace3}}
	chunk5BatchBytesSize, chunk5BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6093), chunk5BatchBytesSize)
	assert.Equal(t, uint64(3149), chunk5BlobSize)
	chunk6 := &encoding.Chunk{Blocks: []*encoding.Block{trace4}}
	chunk6BatchBytesSize, chunk6BlobSize, err := EstimateChunkL1CommitBatchSizeAndBlobSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk6BatchBytesSize)
	assert.Equal(t, uint64(54), chunk6BlobSize)
	batch5 := &encoding.Batch{Chunks: []*encoding.Chunk{chunk5, chunk6}}
	batch5BatchBytesSize, batch5BlobSize, err := EstimateBatchL1CommitBatchSizeAndBlobSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6125), batch5BatchBytesSize)
	assert.Equal(t, uint64(3186), batch5BlobSize)
}

func TestCodecV3ChunkAndBatchCalldataSizeEstimation(t *testing.T) {
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

func TestCodecV3DABatchJSONMarshalUnmarshal(t *testing.T) {
	t.Run("Case 1", func(t *testing.T) {
		jsonStr := `{
			"version": 3,
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

		assert.Equal(t, uint8(3), batch.Version)
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

		expectedHash := common.HexToHash("0x6c693817a272efd00dd1323a533a114bd0a8c63b55816fde36c5784a4125441d")
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
			"version": 4,
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

		assert.Equal(t, uint8(4), batch.Version)
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

		expectedHash := common.HexToHash("0x005661faf2444824b8a3fe1a53958195b197436a0df81b5d1677287bcd1c1923")
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
