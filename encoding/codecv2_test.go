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

func TestCodecV2BlockEncode(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block := &daBlockV0{}
	encoded := hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	daBlock, err := codecv2.NewDABlock(block2, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	daBlock, err = codecv2.NewDABlock(block3, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	daBlock, err = codecv2.NewDABlock(block4, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	daBlock, err = codecv2.NewDABlock(block5, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	daBlock, err = codecv2.NewDABlock(block6, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	daBlock, err = codecv2.NewDABlock(block7, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)

	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	// sanity check: v0 and v2 block encodings are identical
	for _, trace := range []*Block{block2, block3, block4, block5, block6, block7} {
		blockv0, err := codecv0.NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv0 := hex.EncodeToString(blockv0.Encode())

		blockv2, err := codecv2.NewDABlock(trace, 0)
		assert.NoError(t, err)
		encodedv2 := hex.EncodeToString(blockv2.Encode())

		assert.Equal(t, encodedv0, encodedv2)
	}
}

func TestCodecV2ChunkEncode(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
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
	daChunk, err := codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)
}

func TestCodecV2ChunkHash(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
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
	daChunk, err := codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x820f25d806ddea0ccdbfa463ee480da5b6ea3906e8a658417fb5417d0f837f5c", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x4620b3900e8454133448b677cbb2054c5dd61d467d7ebf752bfb12cffff90f40", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x059c6451e83012b405c7e1a38818369012a4a1c87d7d699366eac946d0410d73", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x854fc3136f47ce482ec85ee3325adfa16a1a1d60126e1c119eaaf0c3a9e90f8e", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x2aa220ca7bd1368e59e8053eb3831e30854aa2ec8bd3af65cee350c1c0718ba6", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv2.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xb65521bea7daff75838de07951c3c055966750fb5a270fead5e0e727c32455c3", hash.Hex())
}

func TestCodecV2BatchEncode(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	// empty batch
	batch := &daBatchV1{
		daBatchV0: daBatchV0{
			version: uint8(CodecV2),
		},
	}
	encoded := hex.EncodeToString(batch.Encode())
	assert.Equal(t, "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "020000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101bbc6b98d7d3783730b6208afac839ad37dcf211b9d9e7c83a5f9d02125ddd70000000000000000000000000000000000000000000000000000000000000000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "02000000000000000000000000000000000000000000000000d46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a601fae670a781fb1ea366dad9c02caf4ea1de4f699214c8171f9219b0c72f6ad40000000000000000000000000000000000000000000000000000000000000000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "020000000000000000000000000000000b000000000000000bcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f012e15203534ae3f4cbe1b0f58fe6db6e5c29432115a8ece6ef5550bf2ffce4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ff", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "020000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc53394137000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffff", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "020000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001dd", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "02000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc5339413700000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0000000000000000000000000000000000000000000000000000000000000000", encoded)

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "020000000000000000000000000000002a000000000000002ae7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8013750f6cb783ce2e8fec5a8aff6c45512f2496d6861204b11b6010fb4aa002900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "020000000000000000000000000000002a000000000000002a9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e1347670128f90d5edbcb10d13521824ccc7f47f85aff6e2da01004f9a402854eb3363200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)
}

func TestCodecV2BatchHash(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	// empty batch
	batch := &daBatchV1{
		daBatchV0: daBatchV0{
			version: uint8(CodecV2),
		},
	}
	assert.Equal(t, common.HexToHash("0x8839b8a7b8dfebdc8e829f6fe543578ccdc8da1307e1e1581541a1e2a8fa5592"), batch.Hash())

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x57553c35f981626b4d1a73c816aa8d8fad83c460fc049c5792581763f7e21b13"), daBatch.Hash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x0f8e5b5205c5d809bf09047f37b558f4eb388c9c4eb23291cd97810d06654409"), daBatch.Hash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc59155dc0ae7d7d3fc29f0a9c6042f14dc58e3a1f9c0417f52bac2c4a8b33014"), daBatch.Hash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x417509641fb0c0d1c07d80e64aab13934f828cb4f09608722bf8126a68c04617"), daBatch.Hash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xe9c82b48e2a54c9206f57897cb870536bd22066d2af3d03aafe8a6a39add7635"), daBatch.Hash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x5e3d20c5b3f56cc5a28e7431241b3ce3d484b12cfb0b3228f378b196beeb3a53"), daBatch.Hash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x19b99491401625d92e16f7df6705219cc55e48e4b08db7bc4020e6934076f5f7"), daBatch.Hash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc5daf2ea5a3107c13b2994fb547336a7dca25cd352c051b6d9b9759d77e95fd2"), daBatch.Hash())
}

func TestCodecV2BatchDataHash(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x9f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed541"), daBatch.DataHash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xd46d19f6d48083dc7905a68e6a20ea6a8fbcd445d56b549b324a8485b5b574a6"), daBatch.DataHash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xcaece1705bf2ce5e94154469d910ffe8d102419c5eb3152c0c6d237cf35c885f"), daBatch.DataHash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4"), daBatch.DataHash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d"), daBatch.DataHash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208"), daBatch.DataHash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xe7740182b0948139505b6b296d0c6c6f7717708323e6e687917acad823b559d8"), daBatch.DataHash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x9b0f37c563d27d9717ab16d47075df996c54fe110130df6b11bfd7230e134767"), daBatch.DataHash())
}

func TestCodecV2CalldataSizeEstimation(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2CalldataSize, err := codecv2.EstimateChunkL1CommitCalldataSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk2CalldataSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2CalldataSize, err := codecv2.EstimateBatchL1CommitCalldataSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch2CalldataSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3CalldataSize, err := codecv2.EstimateChunkL1CommitCalldataSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk3CalldataSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3CalldataSize, err := codecv2.EstimateBatchL1CommitCalldataSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch3CalldataSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4CalldataSize, err := codecv2.EstimateChunkL1CommitCalldataSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk4CalldataSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4CalldataSize, err := codecv2.EstimateBatchL1CommitCalldataSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), batch4CalldataSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5CalldataSize, err := codecv2.EstimateChunkL1CommitCalldataSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(120), chunk5CalldataSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6CalldataSize, err := codecv2.EstimateChunkL1CommitCalldataSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(60), chunk6CalldataSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5CalldataSize, err := codecv2.EstimateBatchL1CommitCalldataSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(180), batch5CalldataSize)
}

func TestCodecV2CommitGasEstimation(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2Gas, err := codecv2.EstimateChunkL1CommitGas(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1124), chunk2Gas)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2Gas, err := codecv2.EstimateBatchL1CommitGas(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(157649), batch2Gas)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3Gas, err := codecv2.EstimateChunkL1CommitGas(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1124), chunk3Gas)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3Gas, err := codecv2.EstimateBatchL1CommitGas(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(157649), batch3Gas)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4Gas, err := codecv2.EstimateChunkL1CommitGas(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(3745), chunk4Gas)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4Gas, err := codecv2.EstimateBatchL1CommitGas(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(160302), batch4Gas)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5Gas, err := codecv2.EstimateChunkL1CommitGas(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2202), chunk5Gas)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6Gas, err := codecv2.EstimateChunkL1CommitGas(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(3745), chunk6Gas)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5Gas, err := codecv2.EstimateBatchL1CommitGas(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(163087), batch5Gas)
}

func TestCodecV2BatchSizeAndBlobSizeEstimation(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2BatchBytesSize, chunk2BlobSize, err := codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), chunk2BatchBytesSize)
	assert.Equal(t, uint64(237), chunk2BlobSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2BatchBytesSize, batch2BlobSize, err := codecv2.EstimateBatchL1CommitBatchSizeAndBlobSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(412), batch2BatchBytesSize)
	assert.Equal(t, uint64(237), batch2BlobSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3BatchBytesSize, chunk3BlobSize, err := codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), chunk3BatchBytesSize)
	assert.Equal(t, uint64(2933), chunk3BlobSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3BatchBytesSize, batch3BlobSize, err := codecv2.EstimateBatchL1CommitBatchSizeAndBlobSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5863), batch3BatchBytesSize)
	assert.Equal(t, uint64(2933), batch3BlobSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4BatchBytesSize, chunk4BlobSize, err := codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk4BatchBytesSize)
	assert.Equal(t, uint64(54), chunk4BlobSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	blob4BatchBytesSize, batch4BlobSize, err := codecv2.EstimateBatchL1CommitBatchSizeAndBlobSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), blob4BatchBytesSize)
	assert.Equal(t, uint64(54), batch4BlobSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5BatchBytesSize, chunk5BlobSize, err := codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6093), chunk5BatchBytesSize)
	assert.Equal(t, uint64(3149), chunk5BlobSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6BatchBytesSize, chunk6BlobSize, err := codecv2.EstimateChunkL1CommitBatchSizeAndBlobSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(214), chunk6BatchBytesSize)
	assert.Equal(t, uint64(54), chunk6BlobSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5BatchBytesSize, batch5BlobSize, err := codecv2.EstimateBatchL1CommitBatchSizeAndBlobSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6125), batch5BatchBytesSize)
	assert.Equal(t, uint64(3186), batch5BlobSize)
}

func TestCodecV2BatchL1MessagePopped(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).totalL1MessagePopped)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV1).totalL1MessagePopped)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV1).totalL1MessagePopped)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 37
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), daBatch.(*daBatchV1).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), daBatch.(*daBatchV1).l1MessagePopped) // skip 7, include 3
	assert.Equal(t, uint64(10), daBatch.(*daBatchV1).totalL1MessagePopped)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(257), daBatch.(*daBatchV1).l1MessagePopped) // skip 255, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV1).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 1
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(256), daBatch.(*daBatchV1).l1MessagePopped) // skip 254, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV1).totalL1MessagePopped)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}} // queue index 10
	chunk9 := &Chunk{Blocks: []*Block{block5}}                 // queue index 37-41
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 10
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(32), daBatch.(*daBatchV1).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV1).totalL1MessagePopped)
}

func TestCodecV2BlobEncodingAndHashing(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	batch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded := strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "00609c00fd0600240d0001000000e600f87180843b9aec2e8307a12094c0c4c800baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808301009ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a4100e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec00288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03900985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a0005a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed3200f1030060b26d07d8b028b005", encoded)
	assert.Equal(t, common.HexToHash("0x01bbc6b98d7d3783730b6208afac839ad37dcf211b9d9e7c83a5f9d02125ddd7"), batch.(*daBatchV1).blobVersionedHash)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0060e7159d580094830001000016310002f9162d82cf5502843b9b0a1783119700e28080b915d260806040523480156200001157600080fd5b5060405162001400b2380380833981810160405260a0811037815160208301516040808501805100915193959294830192918464018211639083019060208201858179825181110082820188101794825250918201929091019080838360005b83c357818101510083820152602001620000a9565b50505050905090810190601f16f1578082030080516001836020036101000a0319168191508051604051939291900115012b0001460175015b01a39081015185519093508592508491620001c891600391850001906200026b565b508051620001de90600490602084506005805461ff00190060ff1990911660121716905550600680546001600160a01b0380881619928300161790925560078054928716929091169190911790556200023081620002550062010000600160b01b03191633021790555062000307915050565b60ff19160060ff929092565b828160011615610100020316600290049060005260206000002090601f016020900481019282601f10620002ae5780518380011785de016000010185558215620002de579182015b8202de5782518255916020019190600100c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000002f1565b61119b80620003176000396000f3fe61001004361061010b576000003560e01c80635c975abb116100a257806395d89b411161007114610301578000639dc29fac14610309578063a457c2d714610335578063a9059cbb1461036100578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114610200a55780638456cb59146102cb5780638e50817a146102d3313ce567116100de00571461021d578063395093511461023b5780633f4ba83a146102675780634000c10f191461027106fdde0314610110578063095ea7b31461018d5780631816000ddd146101cd57806323b872e7575b6101186103bb565b6040805160208082005283518183015283519192839290830161015261013a61017f9250508091030090f35b6101b9600480360360408110156101a381351690602001356104519100151582525190819003602001d561046e60fd81169160208101359091169060004074565b6102256104fb60ff90921640025105046f610552565b005b61026f00028705a956610654d520bb3516610662067d56e90135166106d21861075703001f07b856034b085f77c7d5a308db565b6003805420601f600260001961010000600188161502019095169490940493840181900481028201810190925282810052606093909290918301828280156104475780601f1061041c57610100808300540402835291610447565b825b8154815260200180831161042a5782900360001f16820191565b600061046561045e610906565b848461090a565b506001920002548184f6565b6104f18461048d6104ec8560405180606080602861108560002891398a166000908152600160205260408120906104cb81019190915260400001600020549190610b51565b935460ff160511016000610522908116825260002080830193909352604091820120918c168152925290205490610be8565b60000716331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b1b001bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090040060ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606460006508282610ced909052604006ca0ddd900407260c6b6f6e6c792046616374006f727960a0079283918216179091559390921660041561080808550e65086c002511176025006108968dd491824080832093909416825233831661094f5704000180806020018281038252602401806110f36024913960400191fd821661090094223d60228084166000819487168084529482529182902085905581518581005291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200a00c8c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a8b00838383610f61565b610ac881265f60268685808220939093559084168152200054610af7908220409490945580905191937fddf252ad1be2c89b69c2b068fc00378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484111561000be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53610066654d6174683a206164646974696f6e206f766572666c6f7700610c9c147300621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd3008aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e7420746f0020746865207a65726f72657373610d546000600254610d610255902054610d008780838393519293910e2d6101001790557f62e78cea01bee320cd4e42027000b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad6021610e00b68260000ef3221b85839020550f199082610fb540805182600091851691910020565b610f6cb07415610fb02a113c602a00610c428383401e7375627472610063815250fe7472616e736665726275726e20616d6f756e742065786365656400732062616c616e6365617070726f7665616c6c6f7766726f6d646563726561007365642062656c6f775061757361626c653a20746f6b656e7768696c652070006175736564a2646970667358221220e96342bec8f6c2bf72815a39998973b6004c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a77d900fa7ef466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c00001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c00633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda5209500d44b8a9af7813ca8c134a9149a111111110549d2740105c410e61ca4d60312006013290b6398528818e2c8484081888c4890142465a631e63178f9940048f4006ba77adb9be01e898bbbfbc0afba2b64ed71162098740e35ec699633c6a84900670da2d948458ecd9f2e5dc5c5ac4afe3d62cf457cd3507b2eae71e064fab30088531f9c708fd40558dfc698511c4a68234d058c4972da28f0201c4ee550b500e36f0bb42e46bb556d6197be7ea27a3a853e5da024de5ea930350219b1638a00a1dcd41f8222f5d647291e05238c248aa4e028278ad4a9a720f5c16f637166004c4cc255e402cdf64c88e9231dd28a07b8f0ddf1dd7b388875a13dc6d447c000318bca02c54cdfa3621635af1ff932928dfde06038ac9729c301f9f3a3a395008d502ba9e137cc24c14cb4102cf6ba6708b9c812c3ba59a3cbcc5d2aafa8b50097b49fbeb704a22b6137ae9a13b600ad73748768b42756ba338f9854164b1b003f3e23255e4db853a2d3276f061093a37810212ba36db205219fab403242800009178588ad21f754085dd807b09af69e6f06bccbcef8ade3b1f0eb15a077b8005b024ecef4087f261a0d4033355c1e544bd0b0c100276008c420d6d30bc8be00a3ba741063e8b48cf152d3695c0904d477318d4ad46477cdf962443336479f00bd86fd52d4e2a1d23eeddc52463d524b44644abdcd097025bcf9cc636fc1030092cb15b81d7ea667f3ba711624bbf04e992871a6ea4f9d367ba6d46142176f00cdf03e4e19549d2eea45ca804421f6bc33933aab6d478b291bf3619fe15bc900975409d8f3677a87d1b1f7acdb3071b752f3d95c9363ac9c83752f223e45e50079308f554787b4d1f74e389823923f5d268be545466a2dd449963ad25407bd003a18601410b91ca081537f67ea8d527a49adf256f2363346ea35a2fe2768a900091a184f59680df81982c6087efc651f54693a7870aa7c13dcf054c39536c500de8a2dd66955567ff1730dac8533de482aed706ed3417823dd65d058b98899008d54917fd1f70735f7a6a8b1a053c08aac96fb04", encoded)
	assert.Equal(t, common.HexToHash("0x01fae670a781fb1ea366dad9c02caf4ea1de4f699214c8171f9219b0c72f6ad4"), batch.(*daBatchV1).blobVersionedHash)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0020d67d0100740200010000002000df0b80825dc0941a258d17bf244c4df02d0040343a7626a9d321e105808080808001002c0a1801", encoded)
	assert.Equal(t, common.HexToHash("0x012e15203534ae3f4cbe1b0f58fe6db6e5c29432115a8ece6ef5550bf2ffce4c"), batch.(*daBatchV1).blobVersionedHash)

	// this batch only contains L1 txs
	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0020b6550000180001000100300a0c01", encoded)
	assert.Equal(t, common.HexToHash("0x015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370"), batch.(*daBatchV1).blobVersionedHash)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0020b6550000180001000100300a0c01", encoded)
	assert.Equal(t, common.HexToHash("0x015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370"), batch.(*daBatchV1).blobVersionedHash)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0020b6550000180001000100300a0c01", encoded)
	assert.Equal(t, common.HexToHash("0x015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370"), batch.(*daBatchV1).blobVersionedHash)

	// 45 chunks
	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "006024281d0700140d002d000000e6f87180843b9aec2e8307a12094c0c4c8ba00ea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019e00cea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e8006df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec28008bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03998005866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a003e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f100040041e1491b3e82c9b61d60d39a727", encoded)
	assert.Equal(t, common.HexToHash("0x01fc79efca1213db1aa0183865b0a360dc152662cde34ee6a34e7607b96c1c89"), batch.(*daBatchV1).blobVersionedHash)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	batch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = strings.TrimRight(hex.EncodeToString(batch.(*daBatchV1).blob[:]), "0")
	assert.Equal(t, "0060ed16256000449200020000173700f87180843b9aec2e8307a12094c0c4c800baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af6000000808301009ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a4100e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec00288bbaf42a8bf8710101bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf03900985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a0005a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed3200f102f9162d82cf5502843b9b0a17831197e28080b915d26080604052348015006200001157600080fd5b50604051620014b2380380833981810160405260a000811037815160208301516040808501805191519395929483019291846401820011639083019060208201858179825181118282018810179482525091820192009091019080838360005b83c3578181015183820152602001620000a9565b5000505050905090810190601f16f15780820380516001836020036101000a031900168191508051604051939291900115012b01460175015b01a3908101518551009093508592508491620001c8916003918501906200026b565b50805162000100de90600490602084506005805461ff001960ff199091166012171690555060000680546001600160a01b03808816199283161790925560078054928716929000911691909117905562000230816200025562010000600160b01b0319163302001790555062000307915050565b60ff191660ff929092565b828160011615610001000203166002900490600052602060002090601f01602090048101928260001f10620002ae5780518380011785de0160010185558215620002de57918201005b8202de57825182559160200191906001c1565b50620002ec9291f0565b500090565b5b8002ec5760008155600101620002f1565b61119b8062000317600000396000f3fe61001004361061010b5760003560e01c80635c975abb116100a20057806395d89b4111610071146103015780639dc29fac14610309578063a45700c2d714610335578063a9059cbb14610361578063dd62ed3e1461038d576101000b565b1461029d57806370a08231146102a55780638456cb59146102cb578000638e50817a146102d3313ce567116100de571461021d57806339509351146100023b5780633f4ba83a1461026757806340c10f191461027106fdde031461010010578063095ea7b31461018d57806318160ddd146101cd57806323b872e757005b6101186103bb565b6040805160208082528351818301528351919283929000830161015261013a61017f92505080910390f35b6101b960048036036040810010156101a3813516906020013561045191151582525190819003602001d56100046e60fd811691602081013590911690604074565b6102256104fb60ff9092001640025105046f610552565b005b61026f028705a956610654d520bb351661000662067d56e90135166106d218610757031f07b856034b085f77c7d5a308db00565b6003805420601f600260001961010060018816150201909516949094040093840181900481028201810190925282815260609390929091830182828015006104475780601f1061041c576101008083540402835291610447565b825b810054815260200180831161042a57829003601f16820191565b60006104656104005e610906565b848461090a565b5060019202548184f6565b6104f18461048d006104ec85604051806060806028611085602891398a16600090815260016020005260408120906104cb810191909152604001600020549190610b51565b93540060ff160511016000610522908116825260208083019390935260409182012000918c168152925290205490610be8565b600716331461059f5762461bcd60e5001b60040b60248201526a1b9bdd08185b1b1bddd95960aa1b60448201529064000190fd5b6105a7610c49565b610100900460ff16156105f9106f14185d5cd800589b194e881c185d5cd95960826006064606508282610ced909052604006ca000ddd900407260c6b6f6e6c7920466163746f727960a007928391821617909100559390921660041561080808550e65086c2511176025006108968dd49182400080832093909416825233831661094f5704018080602001828103825260240100806110f36024913960400191fd8216610994223d60228084166000819487160080845294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f0071427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92592819003a350831661000a3b25ce8216610a80230ff86023610a8b838383610f61565b610ac881265f00602686858082209390935590841681522054610af790822040949094558090005191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a004df523b3ef9291829003008184841115610be08381815191508051900ba50b008d0bd2fd900300828201610c421b7f536166654d6174683a20616464697469006f6e206f766572666c6f7700610c9c1473621690557f5db9ee0a495bf2e6ff009c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa610cd0a18216610d00481f7f45524332303a206d696e7420746f20746865207a65726f7265737361000d546000600254610d610255902054610d8780838393519293910e2d610100001790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc00544b05a2588216610eaa6021ad6021610eb68260000ef3221b85839020550f00199082610fb5408051826000918516919120565b610f6cb07415610fb02a11003c602a00610c428383401e73756274726163815250fe7472616e73666572620075726e20616d6f756e7420657863656564732062616c616e6365617070726f007665616c6c6f7766726f6d6465637265617365642062656c6f77506175736100626c653a20746f6b656e7768696c6520706175736564a264697066735822120020e96342bec8f6c2bf72815a39998973b64c3bed57770f402e9a7b7eeda026005d4c64736f6c634300060c00331c5a77d9fa7ef466951b2f01f724bca3a582000b63a0e012095745544820636f696e04c001a0235c1a8d40e8c347890397f100a92e6eadbd6422cf7c210e3e1737f0553c633172a02f7c0384ddd06970446e0074229cd96216da62196dc62395bda52095d44b8a9af7df0b80825dc0941a25008d17bf244c4df02d40343a7626a9d321e1058080808080813ea8c134a9149a00111111110549d2740105c410e61ca4d603126013290b6398528818e2c848400081888c4890142465a631e63178f9940048f46ba77adb9be01e898bbbfb80cc00ba2b64ed71162098740e35ec699633c6a849670da2d948458ecd9f2e5dc5c500ac4afe3d62cf457cd3507b2eae71e064fab388531f9c708fd40558dfc69851001c4a68234d058c4972da28f0201c4ee550b5e36f0bb42e46bb556d6197be7e00a27a3a853e5da024de5ea930350219b1638aa1dcd41f8222f5d647291e0523008c248aa4e028278ad4a9a720f5c16f6371664c4cc255e402cdf64c88e9231d00d28a07b8f0ddf1dd7b388875a13dc6d447c0318bca02c54cdfa3621635af1f00f932928dfde06038ac9729c301f9f3a3a3958d502ba9e137cc24c14cb4102c00f6ba6708b9c812c3ba59a3cbcc5d2aafa8b597b49fbeb704a22b6137ae9a1300b600ad73748768b42756ba338f9854164b1b3f3e23255e4db853a2d3276f06001093a37810212ba36db205219fab4032428009178588ad21f754085dd807b0009af69e6f06bccbcef8ade3b1f0eb15a077b85b024ecef4087f261a0d403335005c1e544bd0b0c100276008c420d6d30bc8bea3ba741063e8b48cf152d3695c000904d477318d4ad46477cdf962443336479fbd86fd52d4e2a1d23eeddc5246003d524b44644abdcd097025bcf9cc636fc10392cb15b81d7ea667f3ba71162400bbf04e992871a6ea4f9d367ba6d46142176fcdf03e4e19549d2eea45ca80440021f6bc33933aab6d478b291bf3619fe15bc9975409d8f3677a87d1b1f7acdb003071b752f3d95c9363ac9c83752f223e45e579308f554787b4d1f74e38982300923f5d268be545466a2dd449963ad25407bd3a18601410b91ca081537f67ea008d527a49adf256f2363346ea35a2fe2768a9091a184f59680df81982c6087e00fc651f54693a7870aa7c13dcf054c39536c5de8a2dd66955567ff1730dac850033de482aed706ed3417823dd65d058b988998d54917fe9bb80f5ee4d5c636d00a70ee60a586fdb282babf53e01", encoded)
	assert.Equal(t, common.HexToHash("0x0128f90d5edbcb10d13521824ccc7f47f85aff6e2da01004f9a402854eb33632"), batch.(*daBatchV1).blobVersionedHash)
}

func TestCodecV2BatchBlobDataProofForPointEvaluation(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err := daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "098f1f136f5734039818bee35222d35a96acd7d17120ce8816307527d19badea17d013be5ef696cfbc05b97bb322a587432c2cb23c4848d4d7cb8453c475b38d90b7a581ba5b2cd6a916d139d2b7f28bf6997adb512653f6bdef0bbb7d681c742560fab406fd299c04fc1a464d277f8a8b3a918761888bd0f9a96cb9b2521347131a43b633c4fa01470842d9fe4211bc59c990f69185b80def79b9dfbf039b75", hex.EncodeToString(verifyData))

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "2c440817c5d20c385554774de3fa5d9f32da1dcba228e5cf04f627a41b4b779203f4ef0f3161a3a812523673119d90fb5303248b9fc58c3031a7f4b0937912b8b1530a433168a29443af928876b3d63f4205ba1876d303d56f8456483b9ce91b6ff2b1707726f01c1429cb9d87e4c165ade0ec9e0547ea5721ff442f63d8fcf9ba2f066b07d9b8a0f057e9c0e0e1e56f9a6ec627f9b1cb24866802e15c49c22a", hex.EncodeToString(verifyData))

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "3e935190ba34184cc7bf61a54e030b0ec229292b3025c14c3ef7672b259521cf27c007dc51295c1fe2e05882128a62ef03fb30aaaa4415505929eac7f35424f2a5979717c35155300b0b2d68610aacdd8b0dbb94990168103bfd62985732e3f682370c91c9f2b8f08c6398194e2bb18b83eae765cef6e4e991d91e631dd454953516721962a089a03e4d8f640cd115ede836bad7141e8094317a45ccd04ec842", hex.EncodeToString(verifyData))

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2aa4fe1ee5d7af73b27b10c68f66f4c3700ffe684aa0593cd19690e8075303ca7d395e6d0add8aa5e3e668820713c3377a8bf6769fc8bef4d141ac117962ae0fc2e2606862b3542e5e9b6197f9dcd8a4b126a08b160da6ade484dd4cc1c7be4be", hex.EncodeToString(verifyData))

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2aa4fe1ee5d7af73b27b10c68f66f4c3700ffe684aa0593cd19690e8075303ca7d395e6d0add8aa5e3e668820713c3377a8bf6769fc8bef4d141ac117962ae0fc2e2606862b3542e5e9b6197f9dcd8a4b126a08b160da6ade484dd4cc1c7be4be", hex.EncodeToString(verifyData))

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2aa4fe1ee5d7af73b27b10c68f66f4c3700ffe684aa0593cd19690e8075303ca7d395e6d0add8aa5e3e668820713c3377a8bf6769fc8bef4d141ac117962ae0fc2e2606862b3542e5e9b6197f9dcd8a4b126a08b160da6ade484dd4cc1c7be4be", hex.EncodeToString(verifyData))

	// 15 chunks
	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2, chunk2}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "1bc420092ec4e0af62e7a9243dd6a39ee1341e33032647d3edc16fb4dea5f60a0fad18d05f6f7d57b03dc717f8409489806d89ee5044bea951538682c52d815097e898dbd9a99b1bae2d759ee5f77ac6b6e8fb2cddaf26500532270fd4066e7ae85c450bcbf2cdb4643147091a1ee11ca615b823c97a69cb716d80de6ccafc5823af3a17fc71b72c224edd387abbf4433af013b53f15f394e501e5a3e57af074", hex.EncodeToString(verifyData))

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)
	verifyData, err = daBatch.BlobDataProofForPointEvaluation()
	assert.NoError(t, err)
	assert.Equal(t, "1bea70cbdd3d088c0db7d3dd5a11a2934ec4e7db761195d1e62f9f38a2fd5b325910eea5d881106c394f8d9a80bac8ecc43a86e0b920c5dc93f89caa43b205c2880cc02297edda15b6a14c4481fd15db8209aa52b80aecde6fce0592093eaf0d813c2f081eacb1efa9a8030191e1b780b421b0df42cc64da5e466af6f8cbc20afcb993e6d217440b5b21f2be91abe8620e1518780aa2005ec0a80cb947ebfef9", hex.EncodeToString(verifyData))
}

func TestCodecV2DecodeDAChunksRawTx(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	block0 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	block1 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk0 := &Chunk{Blocks: []*Block{block0, block1}}
	daChunk0, err := codecv2.NewDAChunk(chunk0, 0)
	assert.NoError(t, err)
	chunkBytes0, err := daChunk0.Encode()
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	block3 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk1 := &Chunk{Blocks: []*Block{block2, block3}}
	daChunk1, err := codecv2.NewDAChunk(chunk1, 0)
	assert.NoError(t, err)
	chunkBytes1, err := daChunk1.Encode()
	assert.NoError(t, err)

	originalBatch := &Batch{Chunks: []*Chunk{chunk0, chunk1}}
	batch, err := codecv2.NewDABatch(originalBatch)
	assert.NoError(t, err)

	daChunksRawTx, err := codecv2.DecodeDAChunksRawTx([][]byte{chunkBytes0, chunkBytes1})
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
	err = codecv2.DecodeTxsFromBlob(blob, daChunksRawTx)
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

func TestCodecV2BatchStandardTestCases(t *testing.T) {
	codecv2, err := CodecFromVersion(CodecV2)
	assert.NoError(t, err)

	// Taking into consideration compression, we allow up to 5x of max blob bytes.
	// We then ignore the metadata rows for MaxNumChunksPerBatch chunks.
	nRowsData := 5*maxEffectiveBlobBytes - (int(codecv2.MaxNumChunksPerBatch())*4 + 2)

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
		{chunks: [][]string{{}}, expectedz: "30ba77ffda1712a0cfbbfce9facbc25a2370dc67d6480c686da47b7f181d527e", expectedy: "132f281fd2bc8409114826d70e3148c93b9b4fee7b21c7680e750b3b0c5f6df2", expectedBlobVersionedHash: "015b4e3d3dcd64cc0eb6a5ad535d7a1844a8c4cdad366ec73557bcc533941370", expectedBatchHash: "48c1e31334d6d6dff9f5b38f703c147dc5f0893882fbdcb22ef5fcef0f25f2ff"},
		// single non-empty chunk
		{chunks: [][]string{{"0x010203"}}, expectedz: "13c58784e6eeed40130ab43baa13a1f2d5a6d895c66f554456e00c480568a42d", expectedy: "248ace7f7f0fb3718b80b8cf04be560b97d083a3dbbd79d169e0fe9c80c9668c", expectedBlobVersionedHash: "0161d97a72d600ed5aa264bc8fc409a87e60b768ffb52b9c1106858c2ae57f04", expectedBatchHash: "8918c151720f8497e29ed68ab94a43a32689dcd96784784b81c0fef36b751142"},
		// multiple empty chunks
		{chunks: [][]string{{}, {}}, expectedz: "102e7bf1335a8a86e8ecac2283843eff536555e464bb6ba01a29ff1ca8d4b8cb", expectedy: "033a0272284ae81eb693588e731fc19ad24c44a332405e471966335b37f1a2c2", expectedBlobVersionedHash: "01c0a83d1c0ee2ee06f030ca2f0ec36827b3e9682cbc8c00a27b0bdd3530488b", expectedBatchHash: "6a3e8f32ea6f3025679a912992a7fa813849a7e1f46c8d413fd14d188d497bdb"},
		// multiple non-empty chunks
		{chunks: [][]string{{"0x010203"}, {"0x070809"}}, expectedz: "0ac462d144c9aa1a7538aebd9087e34e9f9590e59b58ffa08f03cd9e43382ed0", expectedy: "6ac7fc7686c900c9e27fd0ca69736cf77016c8b9e8fd3ebab0ee6be1d6c30c93", expectedBlobVersionedHash: "0104efe2cfccfb25e5ae40250af541bd217cae4c9bc14daaf0360a0a36aa2d03", expectedBatchHash: "cfbe74dd07beed8dd9ee2be06ebd869e000148f1886ad6134e6609a3e09520e6"},
		// empty chunk followed by non-empty chunk
		{chunks: [][]string{{}, {"0x010203"}}, expectedz: "1d81a4d2c78fbbf379562a998edde942b2019ec88ede9150a4c2a52a4e271ace", expectedy: "656603441f898b3dd64e0963fea53bfd6a445cb4f838c5caf181186cf45dd7ec", expectedBlobVersionedHash: "0131b881bdc8d8b70a62d9a6f249dc7a48f37428ac10809299489e5e60911f80", expectedBatchHash: "f042d7da2c8af0d9edadd2997ddfc28af646afc513489ac0ab8881c9b18e71bc"},
		// non-empty chunk followed by empty chunk
		{chunks: [][]string{{"0x070809"}, {}}, expectedz: "275116a8ff16b17b90d7287fb567e766d1f79f54f8ac3c6d80e2de59fd34f115", expectedy: "5fea2c1bbed12ccdcf9edef780330ee1d13439de4d3b8f4968f2bda9e4fb8b1f", expectedBlobVersionedHash: "01c44c7e70df601a245e714be4f0aa7c918a0056bff379c20a7128e5926db664", expectedBatchHash: "f9c741682ed579af9c9f21d1c90af830276731ae699ee263fa1278076839e015"},
		// max number of chunks all empty
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}, expectedz: "4583c59de31759dbc54109bb2d5825a36655e71db62225fc5d7d758191e59a6b", expectedy: "0b119ffd6c88037d62e1bee05f609d801c6cc6e724214555b97affe3b852819a", expectedBlobVersionedHash: "013ac7e2db84a2f26ee2cba3a5cabbfffd1f7c053e7ea17add4f84a82cf8285a", expectedBatchHash: "d0846fec4a9158499553e4824cf0ff3fdb01fab93494883d4f8911719ff163ee"},
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
		}, expectedz: "08454da7c353fa9d7c4d044cca3972dab6aa38e583276848b1aec904f5592837", expectedy: "36cbc815c329e864a018cadf25070d62184d570ef031f5b5c8a5385e65babe9c", expectedBlobVersionedHash: "0198009a5e0941a6acb7dcd95a5016d7f25ca92d66fb300cf6f9918102ef66c0", expectedBatchHash: "f20c05457800dc52d87858d72a2b54c223f401b150af00b47994964a348ac96b"},
		// single chunk blob full
		{chunks: [][]string{{repeat(123, nRowsData)}}, expectedz: "63bebf986e2f0fc8bf5f7067108ea4a2b35a5927296e17d5c0bbc5ec04d8dce4", expectedy: "013b762f02e95a62f08977b1a43a017cd84f785b52ebf8ef25e9ebba6c9b76cb", expectedBlobVersionedHash: "01f68a6b3c0ba2ea0406f80f9c88b9905d9b3cc5b2d8ef12923b20fb24b81855", expectedBatchHash: "9effb4102f20c8634655cee9f109215834e7828beadaebe167595f1d1b871689"},
		// multiple chunks blob full
		{chunks: [][]string{{repeat(123, 1111)}, {repeat(231, nRowsData-1111)}}, expectedz: "465e095b082136f20ca975c10eafbb3bf2b71724798da87bd62d3f8795c615dc", expectedy: "6f2ff37b255e0da8b5678a9b1157fdc8a1213c17bd248efd50a4c1540c26295c", expectedBlobVersionedHash: "01da6bdac6237fcba7742cf48868467bf95a5e7f33d16c172b36852e506b46b6", expectedBatchHash: "9631c4dcdbd404272b4682db4592a78e7cd8bf81da34160cc6ff0e9eb4703f70"},
		// max number of chunks only last one non-empty not full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData-1111)}}, expectedz: "1ca17fdb4dea8396d7e2f10ef7b2a587750517df70ec0ce0d853e61310aec0f3", expectedy: "1b686f2eb8d7e3e2325d9101dd799f5e13af8482b402661325545646a9c96ec0", expectedBlobVersionedHash: "019d11fab4509a83623a64b466a00344552fd44421e78726cda537d06c8425d3", expectedBatchHash: "4b369fcaef4a6fd5dbd6bd89e3983f2ff72abf0a19fdabf207c314369500d8e9"},
		// max number of chunks only last one non-empty full blob
		{chunks: [][]string{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {repeat(132, nRowsData)}}, expectedz: "29c684b13d22cb43d81b9b449c281c15126fdc73512606de81c2d3fc9c7793b1", expectedy: "574418d83d77f6096934c2c4281edf61d48925a268411df0e0c818c6d43156d1", expectedBlobVersionedHash: "01f8da934ada220153abee70e85604ef8fbbf98c203b5eae14d23be088a41f45", expectedBatchHash: "5b116a800222102b4cca07a377de69355c33eb3f5262a3b6b1eab37ee680c04a"},
		// max number of chunks but last is empty
		{chunks: [][]string{{repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {repeat(111, 100)}, {}}, expectedz: "16d2883b0797d3420fabf4591f9dbe9f850ce600ce6133c98c9d291d8b3ce0a9", expectedy: "5bdc1ca8f09efa9c544d2b03d565fec500d5347acd5b3fd4d88e881f9459d83a", expectedBlobVersionedHash: "01f51532d6bb0afe8a0a61351888f322cba40dc664408a3201eb761aaba66671", expectedBatchHash: "27af1cbf60123f73bef96464839578875a8bebf39edc786914aa7a0c3a4e3a44"},
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

		blob, blobVersionedHash, z, _, err := codecv2.(*DACodecV2).constructBlobPayload(chunks, int(codecv2.MaxNumChunksPerBatch()), true /* use mock */)
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
				version:              uint8(CodecV2),
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
