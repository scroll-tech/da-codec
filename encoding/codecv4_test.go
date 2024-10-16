package encoding

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodecV4BlockEncode(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	assert.NoError(t, err)

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

	codecV0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	// sanity check: v0 and v4 block encodings are identical
	for _, trace := range []*Block{block2, block3, block4, block5, block6, block7} {
		blockv0, err := codecV0.NewDABlock(trace, 0)
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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	// empty daBatch
	daBatchV3 := &daBatchV3{
		daBatchV0: daBatchV0{
			version: uint8(CodecV4),
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
	assert.Equal(t, "040000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101bbc6b98d7d3783730b6208afac839ad37dcf211b9d9e7c83a5f9d02125ddd700000000000000000000000000000000000000000000000000000000000000000000000063807b2a098f1f136f5734039818bee35222d35a96acd7d17120ce8816307527d19badea17d013be5ef696cfbc05b97bb322a587432c2cb23c4848d4d7cb8453c475b38d", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "04000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a601fae670a781fb1ea366dad9c02caf4ea1de4f699214c8171f9219b0c72f6ad400000000000000000000000000000000000000000000000000000000000000000000000063807b2d2c440817c5d20c385554774de3fa5d9f32da1dcba228e5cf04f627a41b4b779203f4ef0f3161a3a812523673119d90fb5303248b9fc58c3031a7f4b0937912b8", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f012e15203534ae3f4cbe1b0f58fe6db6e5c29432115a8ece6ef5550bf2ffce4c000000000000000000000000000000000000000000000000000000000000000000000000646b6e133e935190ba34184cc7bf61a54e030b0ec229292b3025c14c3ef7672b259521cf27c007dc51295c1fe2e05882128a62ef03fb30aaaa4415505929eac7f35424f2", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000646b6ed030ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000646b6ed030ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "04000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000646b6ed030ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", encoded)

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8013750f6cb783ce2e8fec5a8aff6c45512f2496d6861204b11b6010fb4aa0029000000000000000000000000000000000000000000000000000000000000000000000000646b6ed073c21fcf521e068860a235a4b8f2cdf4a67966ccee1bb46b804b1e7d85333b516c079a4f68903dd18292f1bbdb36b2c94fcefe676931073c2340b2545a504de4", encoded)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "040000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e1347670128f90d5edbcb10d13521824ccc7f47f85aff6e2da01004f9a402854eb33632000000000000000000000000000000000000000000000000000000000000000000000000646b6ed01bea70cbdd3d088c0db7d3dd5a11a2934ec4e7db761195d1e62f9f38a2fd5b325910eea5d881106c394f8d9a80bac8ecc43a86e0b920c5dc93f89caa43b205c2", encoded)
}

func TestCodecV4BatchHash(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	assert.NoError(t, err)

	// empty daBatch
	daBatchV3 := &daBatchV3{
		daBatchV0: daBatchV0{
			version: uint8(CodecV4),
		},
	}
	assert.Equal(t, common.HexToHash("0xdaf0827d02b32d41458aea0d5796dd0072d0a016f9834a2cb1a964d2c6ee135c"), daBatchV3.Hash())

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x0684ec7f79e1950823f3aff20c6a3cde03357eb72027ee663347ac77d46f7565"), daBatch.Hash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x094d6fb43f3bc4af387c8494f5b4d7ba82c9895a0122fbbe34f6a02cb512c564"), daBatch.Hash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xda211c0402d1546fe4964c0e3d61621f6f020c851fd255a2c55419a4e091eae9"), daBatch.Hash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x6bc8b8a6125c4f82afcbf8f190cefd002a61606fb751aca04b99f34a7459f678"), daBatch.Hash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x985335548d6816cf955f39baa9e62ffec7068ac8591f7c7ea5a39d5b4929c29f"), daBatch.Hash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x4ae2e62edaf78d4c9278c170b3ea2b0fb81c95c8875f523dbe889fe5035791ab"), daBatch.Hash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc4120eefe42981b827f5c9a67b8f9b14007bf624694e5702f0f8a665b68832ad"), daBatch.Hash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv4.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xa152b2e1594032ce70be219cfa9781f0840120ac2bf3fcad24893d77c4b74077"), daBatch.Hash())
}

func TestCodecV4BatchDataHash(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	assert.NoError(t, err)

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

func TestCodecV4CalldataSizeEstimation(t *testing.T) {
	codecv4, err := CodecFromVersion(CodecV4)
	assert.NoError(t, err)

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
