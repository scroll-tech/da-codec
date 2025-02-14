package encoding

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/common/hexutil"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

// TestCodecV7DABlockEncodeDecode tests the encoding and decoding of daBlockV7.
func TestCodecV7DABlockEncodeDecode(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	testCases := []struct {
		name                       string
		blockJSONFile              string
		expectedEncode             string
		blockNumber                uint64
		totalL1MessagePoppedBefore uint64
		err                        string
	}{
		{
			name:           "Empty Block",
			blockJSONFile:  "",
			expectedEncode: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			blockNumber:    0,
		},
		{
			name:           "Blocktrace 02",
			blockJSONFile:  "testdata/blockTrace_02.json",
			expectedEncode: "0000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000",
			blockNumber:    2,
		},
		{
			name:           "Blocktrace 03",
			blockJSONFile:  "testdata/blockTrace_03.json",
			expectedEncode: "0000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000",
			blockNumber:    3,
		},
		{
			name:                       "Blocktrace 04 - 1 L1 message + 2 L2 tx",
			blockJSONFile:              "testdata/blockTrace_04.json",
			expectedEncode:             "00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a120000020001",
			blockNumber:                13,
			totalL1MessagePoppedBefore: 9,
		},
		{
			name:                       "Blocktrace 05 - 5 consecutive L1 messages",
			blockJSONFile:              "testdata/blockTrace_05.json",
			expectedEncode:             "00000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120000050005",
			blockNumber:                17,
			totalL1MessagePoppedBefore: 36,
		},
		{
			name:                       "Blocktrace 06 - 3 L1 messages with skipping (error)",
			blockJSONFile:              "testdata/blockTrace_06.json",
			blockNumber:                17,
			totalL1MessagePoppedBefore: 0,
			err:                        "unexpected queue index",
		},
		{
			name:                       "Blocktrace 07 - 2 L1 messages with skipping (error)",
			blockJSONFile:              "testdata/blockTrace_07.json",
			blockNumber:                17,
			totalL1MessagePoppedBefore: 0,
			err:                        "unexpected queue index",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var daBlock DABlock
			if tc.blockJSONFile == "" {
				daBlock = &daBlockV7{}
			} else {
				block := readBlockFromJSON(t, tc.blockJSONFile)
				daBlock, err = codecV7.NewDABlock(block, tc.totalL1MessagePoppedBefore)
				if tc.err == "" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, tc.err)
					return
				}
			}

			encoded := daBlock.Encode()
			require.Equal(t, tc.expectedEncode, hex.EncodeToString(encoded))

			blockDecoded := newDABlockV7WithNumber(tc.blockNumber)
			require.NoError(t, blockDecoded.Decode(encoded))
			assertEqualDABlocks(t, daBlock, blockDecoded)
		})
	}
}

// TestCodecV7DABatchHashEncodeDecode tests the hash, encoding and decoding of daBatchV7.
// It also tests the creation of daBatchV7 FromBytes and FromParams.
func TestCodecV7DABatchHashEncodeDecode(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	testCases := []struct {
		name           string
		batch          *Batch
		expectedEncode string
		expectedHash   string
		creationErr    string
	}{
		{
			name:        "Empty Batch, creation error=no blocks",
			batch:       &Batch{},
			creationErr: "batch must contain at least one block",
		},
		{
			name: "Batch with 1 block,blocktrace 02",
			batch: &Batch{
				Blocks: []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json")},
			},
			expectedEncode: "07000000000000000001a40a4ae0fa894115c6d157d928ae6d5b95e3a38e39d0112086db7a5b94d21e0000000000000000000000000000000000000000000000000000000000000000",
			expectedHash:   "0xae204a7f43d50947ed9033bddac0e8dcebeace076b60c20c4fdfd0284f94f5d4",
		},
		{
			name: "Batch with 1 block, blocktrace 06, creation error=L1 messages not consecutive",
			batch: &Batch{
				Blocks: []*Block{readBlockFromJSON(t, "testdata/blockTrace_06.json")},
			},
			creationErr: "unexpected queue index",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02, 03, 04",
			batch: &Batch{
				InitialL1MessageIndex:  10,
				LastL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks: []*Block{
					readBlockFromJSON(t, "testdata/blockTrace_02.json"),
					readBlockFromJSON(t, "testdata/blockTrace_03.json"),
					replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4),
				},
			},
			expectedEncode: "07000000000000000001f6f07ae03e8a6ead4384c206ac3d38cd453c1da0516dad7608713bd35bb92d0000000000000000000000000000000000000000000000000000000000000000",
			expectedHash:   "0x41c47973d04ecb5d10eca505f0a73964976d7dd4d32f0970d29b006650c85b20",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			daBatchV7i, err := codecV7.NewDABatch(tc.batch)
			if tc.creationErr != "" {
				require.ErrorContains(t, err, tc.creationErr)
				return
			}

			require.NoError(t, err)
			daBatchV7c := daBatchV7i.(*daBatchV7)

			encoded := daBatchV7c.Encode()
			require.Equal(t, tc.expectedEncode, hex.EncodeToString(encoded))
			require.Equal(t, tc.expectedHash, daBatchV7c.Hash().Hex())

			// test DABatchFromBytes
			batchDecoded, err := codecV7.NewDABatchFromBytes(encoded)
			batchDecodedV7 := batchDecoded.(*daBatchV7)
			require.NoError(t, err)
			require.Equal(t, daBatchV7c.version, batchDecodedV7.version)
			require.Equal(t, daBatchV7c.batchIndex, batchDecodedV7.batchIndex)
			require.Equal(t, daBatchV7c.blobVersionedHash, batchDecodedV7.blobVersionedHash)
			require.Equal(t, daBatchV7c.parentBatchHash, batchDecodedV7.parentBatchHash)
			require.Nil(t, batchDecodedV7.blob)
			require.Nil(t, batchDecodedV7.blobBytes)
			require.Equal(t, daBatchV7c.Hash(), batchDecoded.Hash())
			require.Equal(t, daBatchV7c.Encode(), batchDecoded.Encode())

			// test DABatchFromParams
			batchFromParams, err := codecV7.NewDABatchFromParams(daBatchV7c.batchIndex, daBatchV7c.blobVersionedHash, daBatchV7c.parentBatchHash)
			require.NoError(t, err)
			batchFromParamsV7 := batchFromParams.(*daBatchV7)
			require.Equal(t, daBatchV7c.version, batchFromParamsV7.version)
			require.Equal(t, daBatchV7c.batchIndex, batchFromParamsV7.batchIndex)
			require.Equal(t, daBatchV7c.blobVersionedHash, batchFromParamsV7.blobVersionedHash)
			require.Equal(t, daBatchV7c.parentBatchHash, batchFromParamsV7.parentBatchHash)
			require.Nil(t, batchFromParamsV7.blob)
			require.Nil(t, batchFromParamsV7.blobBytes)
			require.Equal(t, daBatchV7c.Hash(), batchFromParams.Hash())
			require.Equal(t, daBatchV7c.Encode(), batchFromParams.Encode())
		})
	}
}

func TestCodecV7BlobEncodingAndHashing(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)
	require.EqualValues(t, CodecV7, codecV7.Version())

	testCases := []struct {
		name                      string
		batch                     *Batch
		creationErr               string
		expectedBlobEncode        string
		expectedBlobVersionedHash string
	}{
		{
			name: "Empty batch",
			batch: &Batch{
				Index:                     1,
				ParentBatchHash:           common.Hash{},
				InitialL1MessageIndex:     0,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.Hash{},
				Blocks:                    []*Block{},
			},
			creationErr: "batch must contain at least one block",
		},
		{
			name: "Batch with 1 block, blocktrace 02",
			batch: &Batch{
				Index:                     1,
				ParentBatchHash:           common.Hash{},
				InitialL1MessageIndex:     0,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.Hash{},
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json")},
			},
			expectedBlobEncode:        "00070000f901606c009d0700240e000002000163807b2a1de9000355418d1e81008400020000f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e002adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa7008e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a034cbd19fea00cd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf871010100bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f007b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bc00ec5bd4aba684835996fc3f879380aac1c09c6eed32f105006032821d60094200a4b00e450116",
			expectedBlobVersionedHash: "0x01a40a4ae0fa894115c6d157d928ae6d5b95e3a38e39d0112086db7a5b94d21e",
		},
		{
			name: "Batch with 1 blocks, blocktrace 04 - 1 L1 message + 1 L2 tx",
			batch: &Batch{
				Index:                     1,
				ParentBatchHash:           common.Hash{},
				InitialL1MessageIndex:     10,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks:                    []*Block{replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobEncode:        "00070000650120a6050300f40400000a00c7436aaec2cfaf39d5be02a02c6ac200089ab264c3e0fd142db682f1cc00040001646b6e137a120000020001df0b8000825dc0941a258d17bf244c4df02d40343a7626a9d321e105808080808006000039066e16790923b039d0f80258",
			expectedBlobVersionedHash: "0x017f5ad1717f1e48ed6a01647d0c038f87d075ea1b712129156ae0b0fa8dbb7a",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 03 + 04",
			batch: &Batch{
				Index:                     1,
				ParentBatchHash:           common.Hash{},
				InitialL1MessageIndex:     10,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), readBlockFromJSON(t, "testdata/blockTrace_03.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobEncode:        "0007000c6801602517156300b49600000a00c7436aaec2cfaf39d5be02a02c6a00c2089ab264c3e0fd142db682f1cc0002000363807b2a1de9000355418d1e810084000263807b2d1a2c0003546c3cbb39e50001646b6e137a120000020001f8007180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0c00a28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf678100e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d0000c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8710101bae6bf68e9a0003fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f7b2cace28d8f0020bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68400835996fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a1783110097e28080b915d260806040523480156200001157600080fd5b5060405162000014b2380380833981810160405260a08110378151602083015160408085018000519151939592948301929184648211639083019060208201858179825181110082820188101794825250918201929091019080838360005b83c357818101510083820152602001620000a9565b50505050905090810190601f16f1578082030080516001836020036101000a0319168191508051604051939291900115012b0001460175015b01a39081015185519093508592508491620001c891600391850001906200026b565b508051620001de90600490602084506005805461ff00190060ff1990911660121716905550600680546001600160a01b0380881619928300161790925560078054928716929091169190911790556200023081620002550062010000600160b01b03191633021790555062000307915050565b60ff19160060ff929092565b828160011615610100020316600290049060005260206000002090601f016020900481019282601f10620002ae5780518380011785de016000010185558215620002de579182015b8202de5782518255916020019190600100c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000002f1565b61119b80620003176000396000f3fe61001004361061010b576000003560e01c80635c975abb116100a257806395d89b411161007114610301578000639dc29fac14610309578063a457c2d714610335578063a9059cbb1461036100578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114610200a55780638456cb59146102cb5780638e50817a146102d3313ce567116100de00571461021d578063395093511461023b5780633f4ba83a146102675780634000c10f191461027106fdde0314610110578063095ea7b31461018d5780631816000ddd146101cd57806323b872e7575b6101186103bb565b6040805160208082005283518183015283519192839290830161015261013a61017f9250508091030090f35b6101b9600480360360408110156101a381351690602001356104519100151582525190819003602001d561046e60fd81169160208101359091169060004074565b6102256104fb60ff90921640025105046f610552565b005b61026f00028705a956610654d520bb3516610662067d56e90135166106d21861075703001f07b856034b085f77c7d5a308db565b6003805420601f600260001961010000600188161502019095169490940493840181900481028201810190925282810052606093909290918301828280156104475780601f1061041c57610100808300540402835291610447565b825b8154815260200180831161042a5782900360001f16820191565b600061046561045e610906565b848461090a565b506001920002548184f6565b6104f18461048d6104ec8560405180606080602861108560002891398a166000908152600160205260408120906104cb81019190915260400001600020549190610b51565b935460ff160511016000610522908116825260002080830193909352604091820120918c168152925290205490610be8565b60000716331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b1b001bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090040060ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606460006508282610ced909052604006ca0ddd900407260c6b6f6e6c792046616374006f727960a0079283918216179091559390921660041561080808550e65086c002511176025006108968dd491824080832093909416825233831661094f5704000180806020018281038252602401806110f36024913960400191fd821661090094223d60228084166000819487168084529482529182902085905581518581005291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200a00c8c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a8b00838383610f61565b610ac881265f60268685808220939093559084168152200054610af7908220409490945580905191937fddf252ad1be2c89b69c2b068fc00378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484111561000be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53610066654d6174683a206164646974696f6e206f766572666c6f7700610c9c147300621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd3008aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e7420746f0020746865207a65726f72657373610d546000600254610d610255902054610d008780838393519293910e2d6101001790557f62e78cea01bee320cd4e42027000b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad6021610e00b68260000ef3221b85839020550f199082610fb540805182600091851691910020565b610f6cb07415610fb02a113c602a00610c428383401e7375627472610063815250fe7472616e736665726275726e20616d6f756e742065786365656400732062616c616e6365617070726f7665616c6c6f7766726f6d646563726561007365642062656c6f775061757361626c653a20746f6b656e7768696c652070006175736564a2646970667358221220e96342bec8f6c2bf72815a39998973b6004c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a77d900fa7ef466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c00001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c00633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda5209500d44b8a9af7df0b80825dc0941a258d17bf244c4df02d40343a7626a9d321e100058080808080814ba8d130a9149a111111110549d2741105c418e61894eb01001240132dcb629c42c818e2c888502022230a0a92a4660ef030c8fc0ddb85e200d215e23516285d6a71d2c1a2a351201ca40faeab44851c1fbf00022ce7407800cf901cb445e0306b08cd4a2ae0724e1a69fa2f7aaa8fd851465eda370fade700ee1a0754a65b8078358317f2b9a460eadb2eb338ac8411a449057b478e3c0a008e0987293e5ce118ae05ccbd6837b82de87a617154940bcebb0b88ffe7152700a9f199051c3311ca647ec728aa797d3ae1518f6aa4e348024239b0a5cb78ba00987e426d486756ee2460452ecaa3d1144d5f81412b92e003774763efe158ac004b52b7a96203be266a9b0232cb47ed216a773ff21a241bbabfc22080979fc200aded1bd0615426425652e36f784c92d96db151ec85cb10329135878563adb60099708967a33656729bf44924e051899c3ab3777f03148f5792a231d948a9de0007c1a68a51ba08e133d2c4db0577f63870f2430af1828b47113227da2e0d100032b92a06a32098f02854be1a42a786eec2e9fb35a97738caf6dd1d57188d3f007d29afe7f90ed912ae39132ffcb9741b8010d4f0f3292f811d01f34eab298800a7589f2030d5ea72f11ea3aa1327a64c4de1727122a0958b27aa7025bbaace0018739ab139fa2c36ec0f45a50f55f369672e65d092da47c48e56db72808bc1006bdb3cf8163c31b92c81d7e15f7ab6ae1b7740b28f67947924ce24fef45eb30017491d54e8e28719eee3946ad529583de2cb11ac09c8a704ec7335f5280e2800e97cc2e7cf7bb9245b1ae02c345dcb73998be05998b0def5f91c591330e65600b1c8bbc266faca3360d72a5d4a6edefc8c3854452460ba4a034b808c385fa800c7967a86a91e7af51660b410b97d40afa4fec3d49e522a995aa5ae6453663c00d46b84fc4ff1520634609db2201a6434008d91f0f1c73e8aa5e9f34056154b0070cd526d386d82fd155bd669540674f0e65aa05d301e9174d2e104a603eac600d1cb417f39838c4716b079e06ca3321aa7336319a40edc4a4cdfdb767a702d0012d526c29611c8d2c10817e39f4bc29d180ce6",
			expectedBlobVersionedHash: "0x01f6f07ae03e8a6ead4384c206ac3d38cd453c1da0516dad7608713bd35bb92d",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     37,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0x3d35d6b71c2769de1a4eb8f603e20f539c53a10c6764a6f5836cf13100000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			expectedBlobEncode:        "0007000c4f016005174d62000495000025003d35d6b71c2769de1a4eb8f603e2000f539c53a10c6764a6f5836cf1310002000363807b2a1de9000355418d1e8100840002646b6ed07a12000005000563807b2d1a2c0003546c3cbb39e50001000000f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceea00cb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf006781e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce0064d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8710101bae6bf6800e9a03fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f7b2cace2008d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4ab00a684835996fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a1700831197e28080b915d260806040523480156200001157600080fd5b5060405100620014b2380380833981810160405260a0811037815160208301516040808500018051915193959294830192918464018211639083019060208201858179820051811182820188101794825250918201929091019080838360005b83c357810081015183820152602001620000a9565b50505050905090810190601f16f1570080820380516001836020036101000a031916819150805160405193929190010015012b01460175015b01a39081015185519093508592508491620001c891600003918501906200026b565b508051620001de9060049060208450600580546100ff001960ff1990911660121716905550600680546001600160a01b0380881600199283161790925560078054928716929091169190911790556200023081620000025562010000600160b01b03191633021790555062000307915050565b6000ff191660ff929092565b828160011615610100020316600290049060005260002060002090601f016020900481019282601f10620002ae578051838001178500de0160010185558215620002de579182015b8202de5782518255916020019100906001c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010001620002f1565b61119b80620003176000396000f3fe61001004361061010b005760003560e01c80635c975abb116100a257806395d89b411161007114610300015780639dc29fac14610309578063a457c2d714610335578063a9059cbb1400610361578063dd62ed3e1461038d5761010b565b1461029d57806370a0823100146102a55780638456cb59146102cb5780638e50817a146102d3313ce56711006100de571461021d578063395093511461023b5780633f4ba83a146102675700806340c10f191461027106fdde0314610110578063095ea7b31461018d5780006318160ddd146101cd57806323b872e7575b6101186103bb565b6040805160002080825283518183015283519192839290830161015261013a61017f9250500080910390f35b6101b9600480360360408110156101a381351690602001356100045191151582525190819003602001d561046e60fd81169160208101359091001690604074565b6102256104fb60ff90921640025105046f610552565b005b0061026f028705a956610654d520bb3516610662067d56e90135166106d21861000757031f07b856034b085f77c7d5a308db565b6003805420601f600260001900610100600188161502019095169490940493840181900481028201810190920052828152606093909290918301828280156104475780601f1061041c57610100008083540402835291610447565b825b8154815260200180831161042a5782009003601f16820191565b600061046561045e610906565b848461090a565b500060019202548184f6565b6104f18461048d6104ec8560405180606080602861001085602891398a166000908152600160205260408120906104cb81019190910052604001600020549190610b51565b935460ff160511016000610522908116008252602080830193909352604091820120918c168152925290205490610be800565b600716331461059f5762461bcd60e51b60040b60248201526a1b9bdd0800185b1b1bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010000900460ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600006064606508282610ced909052604006ca0ddd900407260c6b6f6e6c792046006163746f727960a0079283918216179091559390921660041561080808550e0065086c2511176025006108968dd49182408083209390941682523383166109004f57040180806020018281038252602401806110f36024913960400191fd820016610994223d60228084166000819487168084529482529182902085905581005185815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e005b200ac8c7c3b92592819003a3508316610a3b25ce8216610a80230ff8602300610a8b838383610f61565b610ac881265f60268685808220939093559084160081522054610af7908220409490945580905191937fddf252ad1be2c89b69c200b068fc378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484001115610be08381815191508051900ba50b8d0bd2fd900300828201610c421b007f536166654d6174683a206164646974696f6e206f766572666c6f7700610c009c1473621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e00537bd38aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e740020746f20746865207a65726f72657373610d546000600254610d61025590200054610d8780838393519293910e2d6101001790557f62e78cea01bee320cd4e00420270b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad600021610eb68260000ef3221b85839020550f199082610fb540805182600091850016919120565b610f6cb07415610fb02a113c602a00610c428383401e7375620074726163815250fe7472616e736665726275726e20616d6f756e742065786300656564732062616c616e6365617070726f7665616c6c6f7766726f6d646563007265617365642062656c6f775061757361626c653a20746f6b656e7768696c006520706175736564a2646970667358221220e96342bec8f6c2bf72815a3999008973b64c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00330000001c5a77d9fa7ef466951b2f01f724bca3a5820b63a0e01209574554482063006f696e04c001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e001737f0553c633172a02f7c0384ddd06970446e74229cd96216da62196dc6230095bda52095d44b8a9af7814ba8c130a9143223222222122449930e1105c41800e61894eb0112401329cb622042c818e2c888502022330a0a92a4660ef030c800d41b020bd54b2b52d740a07429c5650a708c469770741f38578d8a1c181f160002fcce819dced01cd046489a753bcd9a5460c71c9ed2a85af4562fbba326bf00b460ee14ce7d8f435fa60f80784f8217f378a760e2db08177bbf8461a44971005b468e2a0a4e0987d33d5cf718d505447668371e2db86dd9425494169c23170010ffcb2b4e52e320a370cc6c28fbf4d1a0a8dbfa28c5a316d548c791841fe50040919ef57441fd956d4883596d9d80325c644c9b29277de58e5624800fd81d00edbe8743b12ea14599aa08f8b0a825cace2c1db5bfa87dfdc8a3916c7e25800041282fbf875bcf37b8c348265c565259bf213a49368cc5a0b617de4348dfac001d16fab58e66929018206a034fce4b9f08023628916c86d48a23408b99c73e001a87f64a4d9d1346aa28a58b089f91f2bcd1ba73dc693b18168865563c3291003965bbd440c8b455498c62cc84d342c5d4102035b72e6cdf5ab378c7e624de00dd778ff8f15b8cedf5c9dfc15bc2b59cc912fe5c1a0d40626a18f8e84ba04200c05c72c688c5cbaccf10d84545b9781ba3dd893ca6604de1717123a0158ae700aa7079bb74d102f3ecb18df95908ec8f924a32aa4cdeceeccc603ada6f8821005a68cb001713afcdf0e02d78a0e410040e097fd1b31d6cdc51caae3eefe6ee003993c2a7af90bde0d4c14f17cfcc70e64e29a99d52ee51fc8b4604f43d41a600eaab794791e14ff27b3fc7de5bfa69e9deb3cd7477e9c22e1acde884264d2500e7089aa03137827df80af1e9d2cfb08c8dbb14a2f9c153cc5036495074f55b0096a019f15da8c7957a46a9de77f51860b425b91d40af7cff31df5e5d2aea5b00a5f065b3677cd66bc4a64f115d6e39e0f0b2a01b943280a2919cf06339caba00e944405dd582e0da526dbedf64c5ab86bb80a998beb1bc5a48dd793cba742000e104490784c7b9b7833eee8418b88ccaf441e4370b38239db665ec3b5055990012c1b67be8dd1ae1c0b61e0a64bca0b78bc73730ef4b0d065e",
			expectedBlobVersionedHash: "0x019122a14fdcf36ccab4f507a6d9d45f3a1d17479e108e05ca4b27341b2da98f",
		},
		// test error cases
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03, but with wrong initialL1MessageIndex",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     21,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			creationErr: "failed to sanity check L1 messages count",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03, but with wrong (not consecutive) block number",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     21,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), readBlockFromJSON(t, "testdata/blockTrace_05.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			creationErr: "invalid block number",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03, but with wrong LastL1MessageQueueHash",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     37,
				InitialL1MessageQueueHash: common.Hash{1},
				LastL1MessageQueueHash:    common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			creationErr: "failed to sanity check lastL1MessageQueueHash",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02, 04 + 05 (L1 messages only), but with non-consecutive L1 messages number across blocks 04 and 05",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     9,
				InitialL1MessageQueueHash: common.Hash{1},
				LastL1MessageQueueHash:    common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 4)},
			},
			creationErr: "failed to sanity check L1 messages count",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02, 06, but with non-consecutive L1 messages number within block 06",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     9,
				InitialL1MessageQueueHash: common.Hash{1},
				LastL1MessageQueueHash:    common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_06.json"), 3)},
			},
			creationErr: "unexpected queue index",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var daBatch DABatch
			daBatch, err := codecV7.NewDABatch(tc.batch)
			if tc.creationErr != "" {
				require.ErrorContains(t, err, tc.creationErr)
				return
			}
			require.NoError(t, err)

			// check correctness of blob and blob hash
			require.Equal(t, tc.expectedBlobEncode, strings.TrimRight(hex.EncodeToString(daBatch.Blob()[:]), "0"))
			require.Equal(t, common.HexToHash(tc.expectedBlobVersionedHash), daBatch.(*daBatchV7).blobVersionedHash)

			// check correctness of blob decoding: blobPayload metadata
			blobPayload, err := codecV7.DecodeBlob(daBatch.Blob())
			require.NoError(t, err)

			require.Equal(t, tc.batch.InitialL1MessageIndex, blobPayload.InitialL1MessageIndex())
			require.Equal(t, tc.batch.InitialL1MessageQueueHash, blobPayload.InitialL1MessageQueueHash())
			require.Equal(t, tc.batch.LastL1MessageQueueHash, blobPayload.LastL1MessageQueueHash())

			// check correctness of decoded blocks and transactions
			require.Equal(t, len(tc.batch.Blocks), len(blobPayload.Blocks()))
			decodedBlocks := blobPayload.Blocks()
			for i, block := range tc.batch.Blocks {
				numL1Messages, _, err := block.NumL1MessagesNoSkipping()
				require.NoError(t, err)

				daBlock := newDABlockV7(block.Header.Number.Uint64(), block.Header.Time, block.Header.BaseFee, block.Header.GasLimit, uint16(block.NumL2Transactions())+numL1Messages, numL1Messages)
				assertEqualDABlocks(t, daBlock, decodedBlocks[i])

				txDataDecoded := TxsToTxsData(blobPayload.Transactions()[i])
				var j int
				for _, txData := range block.Transactions {
					// Decoded blob contains only L2 transactions, L1 transactions need to be read from L1 (by using initialQueueIndex)
					// So in this test we skip checking them.
					if txData.Type == types.L1MessageTxType {
						continue
					}

					assertEqualTransactionData(t, txData, txDataDecoded[j])
					j++
				}
			}
		})
	}
}

func TestCodecV7BatchStandardTestCasesEnableCompression(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	// Apply patches to functions to replace behavior for testing.
	{
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
	}

	repeat := func(element byte, count int) string {
		result := make([]byte, 0, count)
		for i := 0; i < count; i++ {
			result = append(result, element)
		}
		return "0x" + common.Bytes2Hex(result)
	}

	// Taking into consideration compression, we allow up to 5x of max blob bytes minus 5 byte for the blob envelope header.
	// We subtract 82 bytes for the blobPayloadV7 metadata.
	//compressableAvailableBytes := maxEffectiveBlobBytes*5 - 5 - 82
	maxAvailableBytesCompressable := 5*maxEffectiveBlobBytes - 5 - 82
	maxAvailableBytesIncompressable := maxEffectiveBlobBytes - 5 - 82
	// 52 bytes for each block as per daBlockV7 encoding.
	bytesPerBlock := 52

	testCases := []struct {
		name        string
		numBlocks   int
		txData      []string
		creationErr string

		expectedBlobVersionedHash string
	}{
		{
			name:                      "no blocks",
			txData:                    []string{},
			expectedBlobVersionedHash: "0x01c3d5ebe49678dcde7aa2e90b6bd451a11c2718b40aa739aa5f626550435389",
		},
		{
			name:                      "single block, single tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x013b5be233a9a3ef576049b3dbd81b71f62ca2c99fde0e74dfbed59ba0e45bd2",
		},
		{
			name:                      "single block, multiple tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x016591dd97004a0bfd84efee01dd5cb10c477e4300f34dedf428d2cd154fc69d",
		},
		{
			name:                      "multiple blocks, single tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x01890ba0b9db428ca5545d1a58e5ba7735f92395e3dd7811ca1f652280bb1d3f",
		},
		{
			name:                      "multiple blocks, multiple tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x014a47d175874f5b10d95deabe0a3b10ea2bdbc5080ea33b9f1a16a4d3c7395f",
		},
		{
			name:                      "thousands of blocks, multiple tx per block",
			numBlocks:                 10000,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x013e0d8453800705d2addbb1e1b18a32e4f122c1796118e332c12b76ac94f981",
		},
		{
			name:                      "single block, single tx, full blob random data -> data bigger compressed than uncompressed",
			numBlocks:                 1,
			txData:                    []string{generateRandomData(maxAvailableBytesIncompressable - bytesPerBlock)},
			expectedBlobVersionedHash: "0x0116f6c465152096ad21177c0a3f418342550e5c87a64636a900ac53d6737db8",
		},
		{
			name:                      "2 blocks, single tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{generateRandomData(maxAvailableBytesIncompressable/2 - bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01b1c7f234b9f42f09e950d60f9dbf6f5811f0a9abdb85a4a954e731a9ff56d7",
		},
		{
			name:                      "single block, single tx, full blob repeat data",
			numBlocks:                 1,
			txData:                    []string{repeat(0x12, maxAvailableBytesCompressable-bytesPerBlock)},
			expectedBlobVersionedHash: "0x01ce5ed50a28906dd5f1556f6da913c24b6637a1d1aa6ff53d0abfb078e1ac44",
		},
		{
			name:                      "2 blocks, single 2, full blob random data",
			numBlocks:                 2,
			txData:                    []string{repeat(0x12, maxAvailableBytesCompressable/2-bytesPerBlock*2), repeat(0x13, maxAvailableBytesCompressable/2-bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01af3e8f72659c3e4bb6193fe8acc6548589f1a887a0a26ea56fdcae2ac62f81",
		},
		{
			name:        "single block, single tx, full blob random data -> error because 1 byte too big",
			numBlocks:   1,
			txData:      []string{generateRandomData(maxAvailableBytesIncompressable - bytesPerBlock + 1)},
			creationErr: "blob exceeds maximum size",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var blocks []*Block
			for i := 0; i < tc.numBlocks; i++ {
				block := &Block{
					Header: &types.Header{
						Number: big.NewInt(int64(i)),
					},
					Transactions: []*types.TransactionData{},
				}
				for _, data := range tc.txData {
					tx := &types.TransactionData{Type: 0xff, Data: data}
					block.Transactions = append(block.Transactions, tx)
				}
				blocks = append(blocks, block)
			}

			_, blobVersionedHash, _, err := codecV7.(*DACodecV7).constructBlob(&Batch{Blocks: blocks})
			if tc.creationErr != "" {
				require.ErrorContains(t, err, tc.creationErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, common.HexToHash(tc.expectedBlobVersionedHash), blobVersionedHash)
		})
	}
}

func TestCodecV7BatchStandardTestCasesDisableCompression(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	// Apply patches to functions to replace behavior for testing.
	{
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

		// Always disable compression.
		patches.ApplyPrivateMethod(codecV7, "checkCompressedDataCompatibility", func(payloadBytes []byte) ([]byte, bool, error) {
			return nil, false, nil
		})
	}

	repeat := func(element byte, count int) string {
		result := make([]byte, 0, count)
		for i := 0; i < count; i++ {
			result = append(result, element)
		}
		return "0x" + common.Bytes2Hex(result)
	}

	// No compression. max blob bytes minus 5 byte for the blob envelope header.
	// We subtract 82 bytes for the blobPayloadV7 metadata.
	maxAvailableBytes := maxEffectiveBlobBytes - 5 - 82
	// 52 bytes for each block as per daBlockV7 encoding.
	bytesPerBlock := 52

	testCases := []struct {
		name        string
		numBlocks   int
		txData      []string
		creationErr string

		expectedBlobVersionedHash string
	}{
		{
			name:                      "no blocks",
			txData:                    []string{},
			expectedBlobVersionedHash: "0x01a821a71e2f0e7409d257c2b070cd4626825a6de5a2e3eda0099c21c8b16bd9",
		},
		{
			name:                      "single block, single tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x019ed4e5a68c7da4141a94887837d7a405285d2aaedf9701ad98fe7c27af48eb",
		},
		{
			name:                      "single block, multiple tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01943ef319ee733ebbd63e5facf430aa02c0b7da1f3c9eb7e2cb98b8ff63aa04",
		},
		{
			name:                      "multiple blocks, single tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x013182a3b34bf4a390f8d74d35e922c4e116c45872da8b6f69661510d33736d8",
		},
		{
			name:                      "multiple blocks, multiple tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x018077923a1617eae61bb6f296124f937656e9ab0852ce577e8b0f066207fe7e",
		},
		{
			name:        "thousands of blocks, multiple tx per block -> too big error",
			numBlocks:   10000,
			txData:      []string{"0x010203", "0x040506", "0x070809"},
			creationErr: "blob exceeds maximum size",
		},
		{
			name:                      "single block, single tx, full blob random data",
			numBlocks:                 1,
			txData:                    []string{generateRandomData(maxAvailableBytes - bytesPerBlock)},
			expectedBlobVersionedHash: "0x0116f6c465152096ad21177c0a3f418342550e5c87a64636a900ac53d6737db8",
		},
		{
			name:                      "2 blocks, single tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{generateRandomData(maxAvailableBytes/2 - bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x0123aa955d8c0bbc0baca398d017b316dcb5a7716fe0517a3dee563512f67584",
		},
		{
			name:                      "single block, single tx, full blob repeat data",
			numBlocks:                 1,
			txData:                    []string{repeat(0x12, maxAvailableBytes-bytesPerBlock)},
			expectedBlobVersionedHash: "0x019fff94371bb8986d294a036268f6121257cefa6b520f383e327e0dc5a02d9c",
		},
		{
			name:                      "2 blocks, 2 tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{repeat(0x12, maxAvailableBytes/4-bytesPerBlock*2), repeat(0x13, maxAvailableBytes/4-bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01c9a49d50a70ad2aba13c199531fa40d43a909a65d9f19dd565be7259b415ed",
		},
		{
			name:        "single block, single tx, full blob random data -> error because 1 byte too big",
			numBlocks:   1,
			txData:      []string{generateRandomData(maxAvailableBytes - bytesPerBlock + 1)},
			creationErr: "blob exceeds maximum size",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var blocks []*Block
			for i := 0; i < tc.numBlocks; i++ {
				block := &Block{
					Header: &types.Header{
						Number: big.NewInt(int64(i)),
					},
					Transactions: []*types.TransactionData{},
				}
				for _, data := range tc.txData {
					tx := &types.TransactionData{Type: 0xff, Data: data}
					block.Transactions = append(block.Transactions, tx)
				}
				blocks = append(blocks, block)
			}

			_, blobVersionedHash, _, err := codecV7.(*DACodecV7).constructBlob(&Batch{Blocks: blocks})
			if tc.creationErr != "" {
				require.ErrorContains(t, err, tc.creationErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, common.HexToHash(tc.expectedBlobVersionedHash), blobVersionedHash)
		})
	}
}

func TestCodecV7BatchCompressedDataCompatibilityCheck(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	// bypass batch validation checks by calling checkCompressedDataCompatibility directly
	_, compatible, err := codecV7.(*DACodecV7).checkCompressedDataCompatibility([]byte{0})
	require.NoError(t, err)
	require.Equal(t, false, compatible)

	testCases := []struct {
		name             string
		batch            *Batch
		expectCompatible bool
		creationErr      string
	}{
		{
			name: "Single Block 02",
			batch: &Batch{
				Blocks: []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json")},
			},
			expectCompatible: true,
		},
		{
			name: "Single Block 03",
			batch: &Batch{
				Blocks: []*Block{readBlockFromJSON(t, "testdata/blockTrace_03.json")},
			},
			expectCompatible: true,
		},
		{
			name: "Single Block 04",
			batch: &Batch{
				InitialL1MessageIndex:  10,
				LastL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_04.json")},
			},
			expectCompatible: true,
		},
		{
			name: "Single Block 05, only L1 messages",
			batch: &Batch{
				InitialL1MessageIndex:  37,
				LastL1MessageQueueHash: common.HexToHash("0x3d35d6b71c2769de1a4eb8f603e20f539c53a10c6764a6f5836cf13100000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_05.json")},
			},
			expectCompatible: true,
		},
		{
			name: "Single Block 06",
			batch: &Batch{
				Blocks: []*Block{readBlockFromJSON(t, "testdata/blockTrace_06.json")},
			},
			expectCompatible: false,
			creationErr:      "unexpected queue index",
		},
		{
			name: "Single Block 07",
			batch: &Batch{
				Blocks: []*Block{readBlockFromJSON(t, "testdata/blockTrace_07.json")},
			},
			expectCompatible: false,
			creationErr:      "unexpected queue index",
		},
		{
			name: "Multiple Blocks 02, 03, 04",
			batch: &Batch{
				InitialL1MessageIndex:  10,
				LastL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks: []*Block{
					readBlockFromJSON(t, "testdata/blockTrace_02.json"),
					readBlockFromJSON(t, "testdata/blockTrace_03.json"),
					replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4),
				},
			},
			expectCompatible: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			compatible, err = codecV7.CheckBatchCompressedDataCompatibility(tc.batch)
			if tc.creationErr != "" {
				require.ErrorContains(t, err, tc.creationErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectCompatible, compatible)
		})
	}
}

func TestCodecV7DABatchJSONMarshalUnmarshal(t *testing.T) {
	testCases := []struct {
		name         string
		batch        *daBatchV7
		expectedJSON string
	}{
		{
			name: "Case 01",
			batch: &daBatchV7{
				version:           CodecV7,
				batchIndex:        293212,
				blobVersionedHash: common.HexToHash("0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e"),
				parentBatchHash:   common.HexToHash("0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee"),
			},
			expectedJSON: `{
				"version": 7,
				"batch_index": 293212,
				"blob_versioned_hash": "0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e",
				"parent_batch_hash": "0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee"
		}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.batch)
			require.NoError(t, err, "Failed to marshal daBatch")

			// Compare marshaled JSON
			var expectedJSON, actualJSON map[string]interface{}
			err = json.Unmarshal([]byte(tc.expectedJSON), &expectedJSON)
			require.NoError(t, err, "Failed to unmarshal expected JSON string")
			err = json.Unmarshal(data, &actualJSON)
			require.NoError(t, err, "Failed to unmarshal actual JSON string")

			require.Equal(t, expectedJSON, actualJSON, "Marshaled JSON does not match expected JSON")
		})
	}
}

func TestDACodecV7JSONFromBytes(t *testing.T) {
	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	daBatch := &daBatchV7{
		version:           CodecV7,
		batchIndex:        293212,
		blobVersionedHash: common.HexToHash("0x0120096572a3007f75c2a3ff82fa652976eae1c9428ec87ec258a8dcc84f488e"),
		parentBatchHash:   common.HexToHash("0xc37d3f6881f0ca6b02b1dc071483e02d0fe88cf2ff3663bb1ba9aa0dc034faee"),
	}

	outputJSON, err := codecV7.JSONFromBytes(daBatch.Encode())
	require.NoError(t, err, "JSONFromBytes failed")

	var outputMap map[string]interface{}
	err = json.Unmarshal(outputJSON, &outputMap)
	require.NoError(t, err, "Failed to unmarshal output JSON")

	expectedFields := map[string]interface{}{
		"version":             float64(daBatch.version),
		"batch_index":         float64(daBatch.batchIndex),
		"blob_versioned_hash": daBatch.blobVersionedHash.Hex(),
		"parent_batch_hash":   daBatch.parentBatchHash.Hex(),
	}

	require.Len(t, outputMap, len(expectedFields), "Unexpected number of fields in output")
	for key, expectedValue := range expectedFields {
		require.Equal(t, expectedValue, outputMap[key], fmt.Sprintf("Mismatch in field %s", key))
	}
}

func assertEqualDABlocks(t *testing.T, expected, actual DABlock) {
	require.Equal(t, expected.Number(), actual.Number())
	require.Equal(t, expected.NumTransactions(), actual.NumTransactions())
	require.Equal(t, expected.NumL1Messages(), actual.NumL1Messages())
	require.Equal(t, expected.Timestamp(), actual.Timestamp())
	assertEqualBigInt(t, expected.BaseFee(), actual.BaseFee())
	require.Equal(t, expected.GasLimit(), actual.GasLimit())
}

func assertEqualBigInt(t *testing.T, expected, actual *big.Int) {
	if expected == nil && actual != nil {
		require.EqualValues(t, 0, actual.Int64())
	} else if expected != nil && actual == nil {
		require.EqualValues(t, expected.Int64(), 0)
	} else {
		require.EqualValuesf(t, 0, expected.Cmp(actual), "expected: %v, actual: %v", expected, actual)
	}
}

func assertEqualTransactionData(t *testing.T, expected, actual *types.TransactionData) {
	require.Equal(t, expected.Type, actual.Type)
	require.Equal(t, expected.Nonce, actual.Nonce)
	require.Equal(t, expected.TxHash, actual.TxHash)
	require.Equal(t, expected.Gas, actual.Gas)
	assertEqualBigInt(t, expected.GasPrice.ToInt(), actual.GasPrice.ToInt())
	if expected.GasTipCap == nil {
		assertEqualBigInt(t, expected.GasPrice.ToInt(), actual.GasTipCap.ToInt())
	} else {
		assertEqualBigInt(t, expected.GasTipCap.ToInt(), actual.GasTipCap.ToInt())
	}
	if expected.GasFeeCap == nil {
		assertEqualBigInt(t, expected.GasPrice.ToInt(), actual.GasFeeCap.ToInt())
	} else {
		assertEqualBigInt(t, expected.GasFeeCap.ToInt(), actual.GasFeeCap.ToInt())
	}
	//require.Equal(t, expected.From, actual.From)
	require.Equal(t, expected.To, actual.To)
	// legacy tx chainID is derived from the V. However, since the signatures are not valid in the test data we skip this check.
	if expected.Type != types.LegacyTxType {
		assertEqualBigInt(t, expected.ChainId.ToInt(), actual.ChainId.ToInt())
	}
	assertEqualBigInt(t, expected.Value.ToInt(), actual.Value.ToInt())
	require.Equal(t, expected.Data, actual.Data)
	require.Equal(t, expected.IsCreate, actual.IsCreate)
	require.ElementsMatch(t, expected.AccessList, actual.AccessList)
	assertEqualBigInt(t, expected.V.ToInt(), actual.V.ToInt())
	assertEqualBigInt(t, expected.R.ToInt(), actual.R.ToInt())
	assertEqualBigInt(t, expected.S.ToInt(), actual.S.ToInt())
}

func replaceBlockNumber(block *Block, newNumber uint64) *Block {
	block.Header.Number = new(big.Int).SetUint64(newNumber)
	return block
}

var seed int64 = 42

func generateRandomData(size int) string {
	data := make([]byte, size)

	source := rand.NewSource(seed)
	rng := rand.New(source)

	for i := range data {
		data[i] = byte(rng.Intn(256))
	}

	return "0x" + common.Bytes2Hex(data)
}
