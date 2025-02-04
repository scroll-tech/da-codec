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
			expectedEncode: "070000000000000000018c671159176b607e2ec8333a37e1e58593fa6af330e533b45fa440b6b6399c0000000000000000000000000000000000000000000000000000000000000000",
			expectedHash:   "0xe43674f92aee5921602ccbfe555810ab3780b1df847eb7d8f52bce35ee42e709",
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
				InitialL1MessageIndex:  9,
				LastL1MessageQueueHash: common.HexToHash("0x97f93d31db48682539b6a399f76a8ef13b04d40cdd2b12d61177400000000000"),
				Blocks: []*Block{
					readBlockFromJSON(t, "testdata/blockTrace_02.json"),
					readBlockFromJSON(t, "testdata/blockTrace_03.json"),
					replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4),
				},
			},
			expectedEncode: "07000000000000000001feee34d945b6b7020630c7559303cc5a5d5b52be7111998d3e829948cf44390000000000000000000000000000000000000000000000000000000000000000",
			expectedHash:   "0xf547c2b7c24d0094a51c3e3eed36462a08d6c8558e3defd666d38717d0354cad",
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
			expectedBlobEncode:        "0007f9000001606c009d0700240e000002000163807b2a1de9000355418d1e81008400020000f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e002adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa7008e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a034cbd19fea00cd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf871010100bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f007b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bc00ec5bd4aba684835996fc3f879380aac1c09c6eed32f105006032821d60094200a4b00e450116",
			expectedBlobVersionedHash: "0x018c671159176b607e2ec8333a37e1e58593fa6af330e533b45fa440b6b6399c",
		},
		{
			name: "Batch with 1 blocks, blocktrace 04 - 1 L1 message + 1 L2 tx",
			batch: &Batch{
				Index:                     1,
				ParentBatchHash:           common.Hash{},
				InitialL1MessageIndex:     9,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0x97f93d31db48682539b6a399f76a8ef13b04d40cdd2b12d61177400000000000"),
				Blocks:                    []*Block{replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobEncode:        "00076400000120a6fd0200e4040000090097f93d31db48682539b6a399f76a8e00f13b04d40cdd2b12d611774000040001646b6e137a120000020001df0b8082005dc0941a258d17bf244c4df02d40343a7626a9d321e10580808080800600b90000700281c9062076a0f105b",
			expectedBlobVersionedHash: "0x019644784d15ae6866197bdede1eaa73a7b3beb6380413286039ee8b1be28c54",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 03 + 04",
			batch: &Batch{
				Index:                     1,
				ParentBatchHash:           common.Hash{},
				InitialL1MessageIndex:     9,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0x97f93d31db48682539b6a399f76a8ef13b04d40cdd2b12d61177400000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), readBlockFromJSON(t, "testdata/blockTrace_03.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobEncode:        "0007670c00016025170d6300a4960000090097f93d31db48682539b6a399f76a008ef13b04d40cdd2b12d61177400002000363807b2a1de9000355418d1e818400000263807b2d1a2c0003546c3cbb39e50001646b6e137a120000020001f8710080843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca2008a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e9000cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c004d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8710101bae6bf68e9a03f00b2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f7b2cace28d8f2000bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68483005996fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a1783119700e28080b915d260806040523480156200001157600080fd5b5060405162001400b2380380833981810160405260a08110378151602083015160408085018051009151939592948301929184648211639083019060208201858179825181118200820188101794825250918201929091019080838360005b83c357818101518300820152602001620000a9565b50505050905090810190601f16f1578082038000516001836020036101000a0319168191508051604051939291900115012b0100460175015b01a39081015185519093508592508491620001c891600391850100906200026b565b508051620001de90600490602084506005805461ff00196000ff1990911660121716905550600680546001600160a01b0380881619928316001790925560078054928716929091169190911790556200023081620002556200010000600160b01b03191633021790555062000307915050565b60ff19166000ff929092565b828160011615610100020316600290049060005260206000200090601f016020900481019282601f10620002ae5780518380011785de016001000185558215620002de579182015b8202de57825182559160200191906001c100565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000200f1565b61119b80620003176000396000f3fe61001004361061010b576000350060e01c80635c975abb116100a257806395d89b411161007114610301578063009dc29fac14610309578063a457c2d714610335578063a9059cbb1461036157008063dd62ed3e1461038d5761010b565b1461029d57806370a08231146102a5005780638456cb59146102cb5780638e50817a146102d3313ce567116100de57001461021d578063395093511461023b5780633f4ba83a1461026757806340c1000f191461027106fdde0314610110578063095ea7b31461018d57806318160d00dd146101cd57806323b872e7575b6101186103bb565b6040805160208082520083518183015283519192839290830161015261013a61017f9250508091039000f35b6101b9600480360360408110156101a381351690602001356104519115001582525190819003602001d561046e60fd81169160208101359091169060400074565b6102256104fb60ff90921640025105046f610552565b005b61026f02008705a956610654d520bb3516610662067d56e90135166106d218610757031f0007b856034b085f77c7d5a308db565b6003805420601f600260001961010060000188161502019095169490940493840181900481028201810190925282815200606093909290918301828280156104475780601f1061041c57610100808354000402835291610447565b825b8154815260200180831161042a57829003601f0016820191565b600061046561045e610906565b848461090a565b506001920200548184f6565b6104f18461048d6104ec8560405180606080602861108560280091398a166000908152600160205260408120906104cb81019190915260400100600020549190610b51565b935460ff160511016000610522908116825260200080830193909352604091820120918c168152925290205490610be8565b60070016331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b1b1b00ddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090046000ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606460600508282610ced909052604006ca0ddd900407260c6b6f6e6c7920466163746f00727960a0079283918216179091559390921660041561080808550e65086c250011176025006108968dd491824080832093909416825233831661094f5704010080806020018281038252602401806110f36024913960400191fd821661099400223d60228084166000819487168084529482529182902085905581518581520091517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac800c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a8b83008383610f61565b610ac881265f60268685808220939093559084168152205400610af7908220409490945580905191937fddf252ad1be2c89b69c2b068fc37008daa952ba7f163c4a11628f55a4df523b3ef9291829003008184841115610b00e08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53616600654d6174683a206164646974696f6e206f766572666c6f7700610c9c147362001690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38a00eae4b073aa610cd0a18216610d481f7f45524332303a206d696e7420746f2000746865207a65726f72657373610d546000600254610d610255902054610d870080838393519293910e2d6101001790557f62e78cea01bee320cd4e420270b500ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad6021610eb6008260000ef3221b85839020550f199082610fb540805182600091851691912000565b610f6cb07415610fb02a113c602a00610c428383401e7375627472616300815250fe7472616e736665726275726e20616d6f756e742065786365656473002062616c616e6365617070726f7665616c6c6f7766726f6d646563726561730065642062656c6f775061757361626c653a20746f6b656e7768696c652070610075736564a2646970667358221220e96342bec8f6c2bf72815a39998973b64c003bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a77d9fa007ef466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c00100a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c63003172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda52095d4004b8a9af7df0b80825dc0941a258d17bf244c4df02d40343a7626a9d321e105008080808080814ba8d130a9149a111111110549d2741105c418e61894eb01120020132d0b639c42c818e2c84840818c8c282848929a39f03038fd0ddb85e2d20015e23516285d6a71d2c1a2a351201ca40facab44851c1fbf00022ce74078cf00901c9845e0306b08cd4a2a70724e1a69542f7aaa8fd851465eda364face7ee001a0754a6938078358317ba99a460e1db3cb338ac8411a449017b478e3c0a8e000987303e5ce118af05cc7d6837a22db87d617154940bcebb0b88ffe71519a900f199051c3311ca347ec728aa797d3ae1518f69a4ff48024239b0a5eb787a4d00ffa1364c67d6c42460452ec2dbd194485fb9412b92e003774762efe150ac4b0058b7a96a03be266a9b0232cb472d206a773ff2364836708dc22081972f855b00edb3d2615426425652e36f684c12dd6db151ec85cb10129135858562adb69900680963a33684e492f40924e051899c9a79d7be012a8e287bd1686fa4546f80006053c5285d46f88c24e22d833b5f0e9cf69042bce0e25184cc90b64b03848400ae8ac12808269c14eaac86cca999bb30fa7d4dd43b8ac07d77c71554e34f5f00caeb72be43b6846bcec40b7f2edd062004352c7cd04b2049c0bcd36a11e22900d60708bcb5ba5cbcc788ea4489695753b85c9c08e8e8e2892a5cc9ae2a30c6009c666c8e3e8b0dfb4351f987aa79da99903218a5f6163147d0b638c045f05a006f1e540b9e4d6e4b60e8f0173ddbebc65d90ecc6f365be8933697ffaadd98b00a50e1aba18c30ce7714aa5ea14a61ef57f083002f22901d55ccd3e4a00d99d004ff8dc792f97644b039c85a6fb092e73113c172604746a3e876bc28c198aec007f57a2997e79c698b4a44bdccd959f16879a88844f5779600991113f0bf5d80052cf30d543afde04180d446e0be885d47f98da5a4a4552abd4956cce8c57bd0046d8ff1451ca8006bc5316ac418f06b831921e3fd9475d9a3e1e78556d09ae0029d5e6a44d56bf62cb3a8d6a40076fae05da1de31549471d4ea874406ebc7a001ef4236793fdc808270f9a6db446e2746a2c83d48156c9f7bdeddd3d1762510035840526201e073d608ca1b900cf8b416d0e",
			expectedBlobVersionedHash: "0x01feee34d945b6b7020630c7559303cc5a5d5b52be7111998d3e829948cf4439",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03",
			batch: &Batch{
				Index:                     3,
				ParentBatchHash:           common.Hash{2},
				InitialL1MessageIndex:     36,
				InitialL1MessageQueueHash: common.Hash{},
				LastL1MessageQueueHash:    common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                    []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			expectedBlobEncode:        "0007500c0001600517556200049500002400faa13a9ed8937474556dd2ea36be00845199e823322cd63279a3ba300002000363807b2a1de9000355418d1e8184000002646b6ed07a12000005000563807b2d1a2c0003546c3cbb39e50001000000f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb000ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf670081e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce6400d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8710101bae6bf68e900a03fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f7b2cace28d008f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba60084835996fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a1783001197e28080b915d260806040523480156200001157600080fd5b5060405162000014b2380380833981810160405260a0811037815160208301516040808501008051915193959294830192918464018211639083019060208201858179825100811182820188101794825250918201929091019080838360005b83c357818100015183820152602001620000a9565b50505050905090810190601f16f1578000820380516001836020036101000a031916819150805160405193929190011500012b01460175015b01a39081015185519093508592508491620001c891600300918501906200026b565b508051620001de90600490602084506005805461ff00001960ff1990911660121716905550600680546001600160a01b0380881619009283161790925560078054928716929091169190911790556200023081620000025562010000600160b01b03191633021790555062000307915050565b60ff00191660ff929092565b828160011615610100020316600290049060005260200060002090601f016020900481019282601f10620002ae5780518380011785de000160010185558215620002de579182015b8202de5782518255916020019190006001c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010100620002f1565b61119b80620003176000396000f3fe61001004361061010b570060003560e01c80635c975abb116100a257806395d89b411161007114610301005780639dc29fac14610309578063a457c2d714610335578063a9059cbb1461000361578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114006102a55780638456cb59146102cb5780638e50817a146102d3313ce56711610000de571461021d578063395093511461023b5780633f4ba83a146102675780006340c10f191461027106fdde0314610110578063095ea7b31461018d5780630018160ddd146101cd57806323b872e7575b6101186103bb565b6040805160200080825283518183015283519192839290830161015261013a61017f9250508000910390f35b6101b9600480360360408110156101a381351690602001356104005191151582525190819003602001d561046e60fd81169160208101359091160090604074565b6102256104fb60ff90921640025105046f610552565b005b6100026f028705a956610654d520bb3516610662067d56e90135166106d21861070057031f07b856034b085f77c7d5a308db565b6003805420601f600260001961000100600188161502019095169490940493840181900481028201810190925200828152606093909290918301828280156104475780601f1061041c57610100008083540402835291610447565b825b8154815260200180831161042a5782900003601f16820191565b600061046561045e610906565b848461090a565b506000019202548184f6565b6104f18461048d6104ec8560405180606080602861100085602891398a166000908152600160205260408120906104cb81019190915200604001600020549190610b51565b935460ff160511016000610522908116820052602080830193909352604091820120918c168152925290205490610be856005b600716331461059f5762461bcd60e51b60040b60248201526a1b9bdd0818005b1b1bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010000900460ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600600064606508282610ced909052604006ca0ddd900407260c6b6f6e6c792046610063746f727960a0079283918216179091559390921660041561080808550e6500086c2511176025006108968dd491824080832093909416825233831661094f0057040180806020018281038252602401806110f36024913960400191fd821600610994223d60228084166000819487168084529482529182902085905581510085815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b00200ac8c7c3b92592819003a3508316610a3b25ce8216610a80230ff8602361000a8b838383610f61565b610ac881265f60268685808220939093559084168100522054610af7908220409490945580905191937fddf252ad1be2c89b69c2b00068fc378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484110015610be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f00536166654d6174683a206164646974696f6e206f766572666c6f7700610c9c001473621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e53007bd38aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e742000746f20746865207a65726f72657373610d546000600254610d61025590205400610d8780838393519293910e2d6101001790557f62e78cea01bee320cd4e42000270b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad602100610eb68260000ef3221b85839020550f199082610fb540805182600091851600919120565b610f6cb07415610fb02a113c602a00610c428383401e7375627400726163815250fe7472616e736665726275726e20616d6f756e742065786365006564732062616c616e6365617070726f7665616c6c6f7766726f6d646563720065617365642062656c6f775061757361626c653a20746f6b656e7768696c650020706175736564a2646970667358221220e96342bec8f6c2bf72815a3999890073b64c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c0033000000001c5a77d9fa7ef466951b2f01f724bca3a5820b63a0e01209574554482063006f696e04c001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e001737f0553c633172a02f7c0384ddd06970446e74229cd96216da62196dc6230095bda52095d44b8a9af7814ba8c130a9143223222222122449930e1105c41800e61894eb01124013290b639c42c818e2c888502022230a0a92a4660ef030c800d41b020bd54b2b44d740a07429c5490a168c46d770903e68ae2a15b9317e2c0004189c033b3a4373603602c7ace1342b53011773d24ad36fd15b7de48eb2fc00d206f38470eefe38f032dd02c4ab13bc98c73b0513df4638d9dc250c234d8a00db32725451704a389ceee1bac7b82ea0d843bbf9684157cb16a2a2b4e01cb90080f85f5e91911a1f59c231134399a6ef0045b5ad4f473c6a518d741c49c051000e14e95a4f2fea3fd986399835d10958868b82513345a5afc0d18a04f001bb00a3ddf77028d625b493a92a017f16b545c199a5a3162c6ab71f7935920def0f003008e5e5f770ebf906771895899095d4eb377c27c98cb1d8d0f6c27908d9cd009ac3c2bf566b260d0901a236fee45cfa4420e08c12755dd8763f0214997f9200a331d158a9d600c1a48a53ba8cf01989ce9b5877f638601a2301f1ca8a47260032a76c971a0899b62a8e51c04c782d549e1a4252d3ebc2f55b6b82776a6ae200dd7df7888f3f6169afcbfe0ede12ae73265ef87369340081a9e1e7535f023b0002e6911653164f667d82c014aacbc56f8cea4efc98b23585c7c58d8056289e00abc2e5edea751698738fcde66721607f482a915105793b136706d5d1de43cc00d1a12d06b848bcf6860767c1c3925f101824fc45cf76b0716729fbfb9c9bb300e74c029f9e42f6f253073f5d1c33c3953ba5ae76cadec3f32c8d35807b4acc00de57538f62c3b9e4733fffdecb24d1d2b067cf74ffc2e55d34cde9847cad2700e7089aa031378a45f80af1e9d2cfb08c8dbb14a279c333cc5065927074955b0096b01931b2508f2bf58c523decea3dc0684972fb805ef9fed3bebdba54c6b7004ae1cb66cf78d56b84a74ff1ba9c72c0e4650137a83200452391f0ff7254ba00e98f80b82a83e0daa4daa8dfc4cfabb6b893a918a8e179b580ba783c76e94400c209940e088f7bcf839eefec98b96ccbf44164370b38239db665ec3b5055990012c19674c19b3d92c3db4a1810cf82de3016100381b7d5a0e605",
			expectedBlobVersionedHash: "0x014f8d28ab7c68a0a0872636c13b0f473044360dfe43b4f0ab93ce0977cd3a42",
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
				InitialL1MessageIndex:     36,
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
			expectedBlobVersionedHash: "0x01b2f5f5d7c4d370e1ec0d48fc0eca148c7a3a3d2cb60164a09c9bcea29051b9",
		},
		{
			name:                      "single block, single tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x01e8d5e04eae7327123212f9a549b0ee00514a50102919daa37f079c7c853685",
		},
		{
			name:                      "single block, multiple tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x0145c9f4f3954759b572df435c18cc805e06f935e540e2c89c687b232c2428d0",
		},
		{
			name:                      "multiple blocks, single tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x014879b661d2c0d65f52104f3f1545aed4179a5522b8fa40a00f538d3c26ccc8",
		},
		{
			name:                      "multiple blocks, multiple tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01ae9bb3857e66609840d78e3d7ac09f4664ae8e8918da13a8d83e722586402a",
		},
		{
			name:                      "thousands of blocks, multiple tx per block",
			numBlocks:                 10000,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01be8942fe0a3dc77590c9346866824f94f3e6a3b1774119c1e9720f763ede09",
		},
		{
			name:                      "single block, single tx, full blob random data -> data bigger compressed than uncompressed",
			numBlocks:                 1,
			txData:                    []string{generateRandomData(maxAvailableBytesIncompressable - bytesPerBlock)},
			expectedBlobVersionedHash: "0x01f1aea1fe3f8a37ff505bf3aa5895d959c004087c4573bd99dcbfa035d5eb57",
		},
		{
			name:                      "2 blocks, single tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{generateRandomData(maxAvailableBytesIncompressable/2 - bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01813145647585e490c7d14eab5aec876f2363954956e0b8d4658f211d5d1fbc",
		},
		{
			name:                      "single block, single tx, full blob repeat data",
			numBlocks:                 1,
			txData:                    []string{repeat(0x12, maxAvailableBytesCompressable-bytesPerBlock)},
			expectedBlobVersionedHash: "0x01ac3403d7e4484fd5569c1042956cf2e5cadb03802603f4ce8ae890c4bc2414",
		},
		{
			name:                      "2 blocks, single 2, full blob random data",
			numBlocks:                 2,
			txData:                    []string{repeat(0x12, maxAvailableBytesCompressable/2-bytesPerBlock*2), repeat(0x13, maxAvailableBytesCompressable/2-bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01c31afe47f81de670e7e8263d1e8e01e452a3afc296528ebb447895d9572238",
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
			expectedBlobVersionedHash: "0x0156a6430f1a7f819f41f4dfda7453c99693670447257f3f3b2f5a07beb47ae9",
		},
		{
			name:                      "single block, single tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x011557bb7fdefb1a973d852d4f1c1ab46e46b5028a6f702821972d15a3a7bf36",
		},
		{
			name:                      "single block, multiple tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x010506ab63a9d8a3221df8c10fcc83f5fc9c072928b5bbe179386832ac422fa4",
		},
		{
			name:                      "multiple blocks, single tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x01e1c40d1f432836f394263e1f2a11c0704b2d3d94e99e48f589df45559b39c8",
		},
		{
			name:                      "multiple blocks, multiple tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01199ab5ee3c5c212843bffe27f07b0e85de1fc1f4e1fb8a7c4edbeb545397d6",
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
			expectedBlobVersionedHash: "0x01f1aea1fe3f8a37ff505bf3aa5895d959c004087c4573bd99dcbfa035d5eb57",
		},
		{
			name:                      "2 blocks, single tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{generateRandomData(maxAvailableBytes/2 - bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x016a8c8e6a56f7a2895b3c5f75dd34a4b8248e0b47d60fca576fa60c571a5812",
		},
		{
			name:                      "single block, single tx, full blob repeat data",
			numBlocks:                 1,
			txData:                    []string{repeat(0x12, maxAvailableBytes-bytesPerBlock)},
			expectedBlobVersionedHash: "0x01ddad97c4d0eaa751c9e74d1a4a805da9434802ce61572ac0b5a87074230bc8",
		},
		{
			name:                      "2 blocks, 2 tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{repeat(0x12, maxAvailableBytes/4-bytesPerBlock*2), repeat(0x13, maxAvailableBytes/4-bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x0126e942bc804b28f9f33c481ef6235e0affcda37be0e4281645067ed2577fe3",
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
				InitialL1MessageIndex:  9,
				LastL1MessageQueueHash: common.HexToHash("0x97f93d31db48682539b6a399f76a8ef13b04d40cdd2b12d61177400000000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_04.json")},
			},
			expectCompatible: true,
		},
		{
			name: "Single Block 05, only L1 messages",
			batch: &Batch{
				InitialL1MessageIndex:  36,
				LastL1MessageQueueHash: common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
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
			name: "Multiple Blocks 02, 03, 04, 05",
			batch: &Batch{
				InitialL1MessageIndex:  9,
				LastL1MessageQueueHash: common.HexToHash("0x97f93d31db48682539b6a399f76a8ef13b04d40cdd2b12d61177400000000000"),
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
