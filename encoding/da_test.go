package encoding

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/scroll-tech/go-ethereum/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scroll-tech/da-codec/encoding/zstd"
)

func TestMain(m *testing.M) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.LogfmtFormat()))
	glogger.Verbosity(log.LvlInfo)
	log.Root().SetHandler(glogger)

	code := m.Run()
	os.Exit(code)
}

func TestUtilFunctions(t *testing.T) {
	block1 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	block2 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	block3 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	block4 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	block5 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	block6 := readBlockFromJSON(t, "testdata/blockTrace_07.json")

	chunk1 := &Chunk{Blocks: []*Block{block1, block2}}
	chunk2 := &Chunk{Blocks: []*Block{block3, block4}}
	chunk3 := &Chunk{Blocks: []*Block{block5, block6}}

	batch := &Batch{Chunks: []*Chunk{chunk1, chunk2, chunk3}}

	// Test Block methods
	assert.Equal(t, uint64(0), block1.NumL1Messages(0))
	assert.Equal(t, uint64(2), block1.NumL2Transactions())
	assert.Equal(t, uint64(0), block2.NumL1Messages(0))
	assert.Equal(t, uint64(1), block2.NumL2Transactions())
	assert.Equal(t, uint64(11), block3.NumL1Messages(0))
	assert.Equal(t, uint64(1), block3.NumL2Transactions())
	assert.Equal(t, uint64(42), block4.NumL1Messages(0))
	assert.Equal(t, uint64(0), block4.NumL2Transactions())
	assert.Equal(t, uint64(10), block5.NumL1Messages(0))
	assert.Equal(t, uint64(0), block5.NumL2Transactions())
	assert.Equal(t, uint64(257), block6.NumL1Messages(0))
	assert.Equal(t, uint64(0), block6.NumL2Transactions())

	// Test Chunk methods
	assert.Equal(t, uint64(0), chunk1.NumL1Messages(0))
	assert.Equal(t, uint64(3), chunk1.NumL2Transactions())
	crc1Max, err := chunk1.CrcMax()
	assert.NoError(t, err)
	assert.Equal(t, uint64(11), crc1Max)
	assert.Equal(t, uint64(3), chunk1.NumTransactions())
	assert.Equal(t, uint64(1194994), chunk1.TotalGasUsed())

	assert.Equal(t, uint64(42), chunk2.NumL1Messages(0))
	assert.Equal(t, uint64(1), chunk2.NumL2Transactions())
	crc2Max, err := chunk2.CrcMax()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), crc2Max)
	assert.Equal(t, uint64(7), chunk2.NumTransactions())
	assert.Equal(t, uint64(144000), chunk2.TotalGasUsed())

	assert.Equal(t, uint64(257), chunk3.NumL1Messages(0))
	assert.Equal(t, uint64(0), chunk3.NumL2Transactions())
	chunk3.Blocks[0].RowConsumption = nil
	crc3Max, err := chunk3.CrcMax()
	assert.Error(t, err)
	assert.EqualError(t, err, "block (17, 0x003fee335455c0c293dda17ea9365fe0caa94071ed7216baf61f7aeb808e8a28) has nil RowConsumption")
	assert.Equal(t, uint64(0), crc3Max)
	assert.Equal(t, uint64(5), chunk3.NumTransactions())
	assert.Equal(t, uint64(240000), chunk3.TotalGasUsed())

	// euclid chunk
	chunk3.Blocks[0].RowConsumption = nil
	chunk3.Blocks[1].RowConsumption = nil
	crc3Max, err = chunk3.CrcMax()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), crc3Max)

	// Test Batch methods
	assert.Equal(t, block6.Header.Root, batch.StateRoot())
	assert.Equal(t, block6.WithdrawRoot, batch.WithdrawRoot())
}

func TestConvertTxDataToRLPEncoding(t *testing.T) {
	blocks := []*Block{
		readBlockFromJSON(t, "testdata/blockTrace_02.json"),
		readBlockFromJSON(t, "testdata/blockTrace_03.json"),
		readBlockFromJSON(t, "testdata/blockTrace_04.json"),
		readBlockFromJSON(t, "testdata/blockTrace_05.json"),
		readBlockFromJSON(t, "testdata/blockTrace_06.json"),
		readBlockFromJSON(t, "testdata/blockTrace_07.json"),
	}

	for _, block := range blocks {
		for _, txData := range block.Transactions {
			if txData.Type == types.L1MessageTxType {
				continue
			}

			rlpTxData, err := convertTxDataToRLPEncoding(txData)
			assert.NoError(t, err)
			var tx types.Transaction
			err = tx.UnmarshalBinary(rlpTxData)
			assert.NoError(t, err)
			assert.Equal(t, txData.TxHash, tx.Hash().Hex())
		}
	}
}

func TestEmptyBatchRoots(t *testing.T) {
	emptyBatch := &Batch{Chunks: []*Chunk{}}
	assert.Equal(t, common.Hash{}, emptyBatch.StateRoot())
	assert.Equal(t, common.Hash{}, emptyBatch.WithdrawRoot())
}

func TestBlobCompressDecompress(t *testing.T) {
	blobString := "0060e7159d580094830001000016310002f9162d82cf5502843b9b0a1783119700e28080b915d260806040523480156200001157600080fd5b5060405162001400b2380380833981810160405260a0811037815160208301516040808501805100915193959294830192918464018211639083019060208201858179825181110082820188101794825250918201929091019080838360005b83c357818101510083820152602001620000a9565b50505050905090810190601f16f1578082030080516001836020036101000a0319168191508051604051939291900115012b0001460175015b01a39081015185519093508592508491620001c891600391850001906200026b565b508051620001de90600490602084506005805461ff00190060ff1990911660121716905550600680546001600160a01b0380881619928300161790925560078054928716929091169190911790556200023081620002550062010000600160b01b03191633021790555062000307915050565b60ff19160060ff929092565b828160011615610100020316600290049060005260206000002090601f016020900481019282601f10620002ae5780518380011785de016000010185558215620002de579182015b8202de5782518255916020019190600100c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000002f1565b61119b80620003176000396000f3fe61001004361061010b576000003560e01c80635c975abb116100a257806395d89b411161007114610301578000639dc29fac14610309578063a457c2d714610335578063a9059cbb1461036100578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114610200a55780638456cb59146102cb5780638e50817a146102d3313ce567116100de00571461021d578063395093511461023b5780633f4ba83a146102675780634000c10f191461027106fdde0314610110578063095ea7b31461018d5780631816000ddd146101cd57806323b872e7575b6101186103bb565b6040805160208082005283518183015283519192839290830161015261013a61017f9250508091030090f35b6101b9600480360360408110156101a381351690602001356104519100151582525190819003602001d561046e60fd81169160208101359091169060004074565b6102256104fb60ff90921640025105046f610552565b005b61026f00028705a956610654d520bb3516610662067d56e90135166106d21861075703001f07b856034b085f77c7d5a308db565b6003805420601f600260001961010000600188161502019095169490940493840181900481028201810190925282810052606093909290918301828280156104475780601f1061041c57610100808300540402835291610447565b825b8154815260200180831161042a5782900360001f16820191565b600061046561045e610906565b848461090a565b506001920002548184f6565b6104f18461048d6104ec8560405180606080602861108560002891398a166000908152600160205260408120906104cb81019190915260400001600020549190610b51565b935460ff160511016000610522908116825260002080830193909352604091820120918c168152925290205490610be8565b60000716331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b1b001bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090040060ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606460006508282610ced909052604006ca0ddd900407260c6b6f6e6c792046616374006f727960a0079283918216179091559390921660041561080808550e65086c002511176025006108968dd491824080832093909416825233831661094f5704000180806020018281038252602401806110f36024913960400191fd821661090094223d60228084166000819487168084529482529182902085905581518581005291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200a00c8c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a8b00838383610f61565b610ac881265f60268685808220939093559084168152200054610af7908220409490945580905191937fddf252ad1be2c89b69c2b068fc00378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484111561000be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53610066654d6174683a206164646974696f6e206f766572666c6f7700610c9c147300621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd3008aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e7420746f0020746865207a65726f72657373610d546000600254610d610255902054610d008780838393519293910e2d6101001790557f62e78cea01bee320cd4e42027000b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad6021610e00b68260000ef3221b85839020550f199082610fb540805182600091851691910020565b610f6cb07415610fb02a113c602a00610c428383401e7375627472610063815250fe7472616e736665726275726e20616d6f756e742065786365656400732062616c616e6365617070726f7665616c6c6f7766726f6d646563726561007365642062656c6f775061757361626c653a20746f6b656e7768696c652070006175736564a2646970667358221220e96342bec8f6c2bf72815a39998973b6004c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a77d900fa7ef466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c00001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c00633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda5209500d44b8a9af7813ca8c134a9149a111111110549d2740105c410e61ca4d60312006013290b6398528818e2c8484081888c4890142465a631e63178f9940048f4006ba77adb9be01e898bbbfbc0afba2b64ed71162098740e35ec699633c6a84900670da2d948458ecd9f2e5dc5c5ac4afe3d62cf457cd3507b2eae71e064fab30088531f9c708fd40558dfc698511c4a68234d058c4972da28f0201c4ee550b500e36f0bb42e46bb556d6197be7ea27a3a853e5da024de5ea930350219b1638a00a1dcd41f8222f5d647291e05238c248aa4e028278ad4a9a720f5c16f637166004c4cc255e402cdf64c88e9231dd28a07b8f0ddf1dd7b388875a13dc6d447c000318bca02c54cdfa3621635af1ff932928dfde06038ac9729c301f9f3a3a395008d502ba9e137cc24c14cb4102cf6ba6708b9c812c3ba59a3cbcc5d2aafa8b50097b49fbeb704a22b6137ae9a13b600ad73748768b42756ba338f9854164b1b003f3e23255e4db853a2d3276f061093a37810212ba36db205219fab403242800009178588ad21f754085dd807b09af69e6f06bccbcef8ade3b1f0eb15a077b8005b024ecef4087f261a0d4033355c1e544bd0b0c100276008c420d6d30bc8be00a3ba741063e8b48cf152d3695c0904d477318d4ad46477cdf962443336479f00bd86fd52d4e2a1d23eeddc52463d524b44644abdcd097025bcf9cc636fc1030092cb15b81d7ea667f3ba711624bbf04e992871a6ea4f9d367ba6d46142176f00cdf03e4e19549d2eea45ca804421f6bc33933aab6d478b291bf3619fe15bc900975409d8f3677a87d1b1f7acdb3071b752f3d95c9363ac9c83752f223e45e50079308f554787b4d1f74e389823923f5d268be545466a2dd449963ad25407bd003a18601410b91ca081537f67ea8d527a49adf256f2363346ea35a2fe2768a900091a184f59680df81982c6087efc651f54693a7870aa7c13dcf054c39536c500de8a2dd66955567ff1730dac8533de482aed706ed3417823dd65d058b98899008d54917fd1f70735f7a6a8b1a053c08aac96fb04"
	blobBytes, err := hex.DecodeString(blobString)
	assert.NoError(t, err)

	compressed, err := zstd.CompressScrollBatchBytesLegacy(blobBytes)
	assert.NoError(t, err)

	blob, err := makeBlobCanonical(compressed)
	assert.NoError(t, err)

	res := bytesFromBlobCanonical(blob)
	compressedBytes := res[:]
	compressedBytes = append(zstdMagicNumber, compressedBytes...)

	decompressedBlobBytes, err := decompressScrollBlobToBatch(compressedBytes)
	assert.NoError(t, err)
	assert.Equal(t, blobBytes, decompressedBlobBytes)
}

func readBlockFromJSON(t *testing.T, filename string) *Block {
	data, err := os.ReadFile(filename)
	assert.NoError(t, err)

	block := &Block{}
	assert.NoError(t, json.Unmarshal(data, block))
	return block
}

func TestMessageQueueV2EncodeRollingHash(t *testing.T) {
	testCases := []struct {
		name           string
		input          common.Hash
		expectedOutput common.Hash
	}{
		{
			"zero hash",
			common.Hash{},
			common.Hash{},
		},
		{
			"all bits set",
			common.Hash{
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
			},
			common.Hash{
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			"random bytes",
			common.Hash{
				0x00, 0x11, 0x22, 0x33,
				0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xAA, 0xBB,
				0xCC, 0xDD, 0xEE, 0xFF,
				0x00, 0x11, 0x22, 0x33,
				0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xAA, 0xBB,
				0xCC, 0xDD, 0xEE, 0xFF,
			},
			common.Hash{
				0x00, 0x11, 0x22, 0x33,
				0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xAA, 0xBB,
				0xCC, 0xDD, 0xEE, 0xFF,
				0x00, 0x11, 0x22, 0x33,
				0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xAA, 0xBB,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			"random hash",
			common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567800000000"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			modified := messageQueueV2EncodeRollingHash(tc.input)
			assert.Equal(t, tc.expectedOutput, modified)
		})
	}
}

func TestTxsToTxsData_L1Message(t *testing.T) {
	msg := &types.L1MessageTx{
		QueueIndex: 100,
		Gas:        99,
		To:         &common.Address{0x01, 0x02, 0x03},
		Value:      new(big.Int).SetInt64(1337),
		Data:       []byte{0x01, 0x02, 0x03},
		Sender:     common.Address{0x04, 0x05, 0x06},
	}

	tx := types.NewTx(msg)

	txData := TxsToTxsData([]*types.Transaction{tx})
	require.Len(t, txData, 1)

	decoded, err := l1MessageFromTxData(txData[0])
	require.NoError(t, err)

	require.Equal(t, tx.Hash(), types.NewTx(decoded).Hash())
}
