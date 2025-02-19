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
	"github.com/stretchr/testify/assert"
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
			totalL1MessagePoppedBefore: 10,
		},
		{
			name:                       "Blocktrace 05 - 5 consecutive L1 messages",
			blockJSONFile:              "testdata/blockTrace_05.json",
			expectedEncode:             "00000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120000050005",
			blockNumber:                17,
			totalL1MessagePoppedBefore: 37,
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
			expectedEncode: "07000000000000000001fe584c5ad4177f0f204262f2dc663592702762b363509d726c2c6e05d6f3960000000000000000000000000000000000000000000000000000000000000000",
			expectedHash:   "0x6f7e34f79b096f96f989200c353ef3875fda0e8372690e09c360be865e161b50",
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
				PostL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks: []*Block{
					readBlockFromJSON(t, "testdata/blockTrace_02.json"),
					readBlockFromJSON(t, "testdata/blockTrace_03.json"),
					replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4),
				},
			},
			expectedEncode: "070000000000000000012f5d0b0130addfce5502c7ce3d04945634fa80efd4b996ce71e1f2203ced3f0000000000000000000000000000000000000000000000000000000000000000",
			expectedHash:   "0x4eb67346d4060cde3f68100ae247e30de7b2f908934b58de581a4f2930bb6810",
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
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.Hash{},
				Blocks:                 []*Block{},
			},
			creationErr: "batch must contain at least one block",
		},
		{
			name: "Batch with 1 block, blocktrace 02",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.Hash{},
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json")},
			},
			expectedBlobEncode:        "00070000f9016064009d0700240e000002000163807b2a1de9000355418d1e81008400020000f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e002adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa7008e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a034cbd19fea00cd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf871010100bae6bf68e9a03fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f007b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bc00ec5bd4aba684835996fc3f879380aac1c09c6eed32f105006032821d6009420094b00e410116",
			expectedBlobVersionedHash: "0x01fe584c5ad4177f0f204262f2dc663592702762b363509d726c2c6e05d6f396",
		},
		{
			name: "Batch with 1 blocks, blocktrace 04 - 1 L1 message + 1 L2 tx",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks:                 []*Block{replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobEncode:        "000700006201209eed0200d4040000c7436aaec2cfaf39d5be02a02c6ac2089a00b264c3e0fd142db682f1cc00040001646b6e137a120000020001df0b80825d00c0941a258d17bf244c4df02d40343a7626a9d321e105808080808005003906006e16790923b039116001",
			expectedBlobVersionedHash: "0x01613f6d2f90590578d58e46f4ee246bf7727f1a85f01c76a327c499a2372481",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 03 + 04",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), readBlockFromJSON(t, "testdata/blockTrace_03.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobEncode:        "0007000c6601601d1705630094960000c7436aaec2cfaf39d5be02a02c6ac208009ab264c3e0fd142db682f1cc0002000363807b2a1de9000355418d1e818400000263807b2d1a2c0003546c3cbb39e50001646b6e137a120000020001f8718000843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a00152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90c00c32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c4d001996b9b5243c578fd7f51bfaec288bbaf42a8bf8710101bae6bf68e9a03fb200bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f7b2cace28d8f20bd00e27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68483590096fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a17831197e2008080b915d260806040523480156200001157600080fd5b50604051620014b200380380833981810160405260a08110378151602083015160408085018051910051939592948301929184648211639083019060208201858179825181118282000188101794825250918201929091019080838360005b83c357818101518382000152602001620000a9565b50505050905090810190601f16f1578082038051006001836020036101000a0319168191508051604051939291900115012b0146000175015b01a39081015185519093508592508491620001c891600391850190006200026b565b508051620001de90600490602084506005805461ff001960ff001990911660121716905550600680546001600160a01b0380881619928316170090925560078054928716929091169190911790556200023081620002556201000000600160b01b03191633021790555062000307915050565b60ff191660ff00929092565b828160011615610100020316600290049060005260206000209000601f016020900481019282601f10620002ae5780518380011785de016001010085558215620002de579182015b8202de57825182559160200191906001c156005b50620002ec9291f0565b5090565b5b8002ec5760008155600101620002f100565b61119b80620003176000396000f3fe61001004361061010b576000356000e01c80635c975abb116100a257806395d89b4111610071146103015780639d00c29fac14610309578063a457c2d714610335578063a9059cbb1461036157800063dd62ed3e1461038d5761010b565b1461029d57806370a08231146102a5570080638456cb59146102cb5780638e50817a146102d3313ce567116100de57140061021d578063395093511461023b5780633f4ba83a1461026757806340c10f00191461027106fdde0314610110578063095ea7b31461018d57806318160ddd00146101cd57806323b872e7575b6101186103bb565b6040805160208082528300518183015283519192839290830161015261013a61017f92505080910390f3005b6101b9600480360360408110156101a381351690602001356104519115150082525190819003602001d561046e60fd81169160208101359091169060407400565b6102256104fb60ff90921640025105046f610552565b005b61026f02870005a956610654d520bb3516610662067d56e90135166106d218610757031f0700b856034b085f77c7d5a308db565b6003805420601f600260001961010060010088161502019095169490940493840181900481028201810190925282815260006093909290918301828280156104475780601f1061041c57610100808354040002835291610447565b825b8154815260200180831161042a57829003601f1600820191565b600061046561045e610906565b848461090a565b506001920254008184f6565b6104f18461048d6104ec8560405180606080602861108560289100398a166000908152600160205260408120906104cb81019190915260400160000020549190610b51565b935460ff160511016000610522908116825260208000830193909352604091820120918c168152925290205490610be8565b60071600331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b1b1bdd00d95960aa1b604482015290640190fd5b6105a7610c49565b610100900460ff0016156105f9106f14185d5cd8589b194e881c185d5cd9596082600606460650008282610ced909052604006ca0ddd900407260c6b6f6e6c7920466163746f72007960a0079283918216179091559390921660041561080808550e65086c251100176025006108968dd491824080832093909416825233831661094f5704018000806020018281038252602401806110f36024913960400191fd821661099422003d60228084166000819487168084529482529182902085905581518581529100517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c700c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a8b83830083610f61565b610ac881265f60268685808220939093559084168152205461000af7908220409490945580905191937fddf252ad1be2c89b69c2b068fc378d00aa952ba7f163c4a11628f55a4df523b3ef9291829003008184841115610be0008381815191508051900ba50b8d0bd2fd900300828201610c421b7f53616665004d6174683a206164646974696f6e206f766572666c6f7700610c9c147362160090557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aea00e4b073aa610cd0a18216610d481f7f45524332303a206d696e7420746f2074006865207a65726f72657373610d546000600254610d610255902054610d878000838393519293910e2d6101001790557f62e78cea01bee320cd4e420270b5ea0074000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad6021610eb6820060000ef3221b85839020550f199082610fb540805182600091851691912056005b610f6cb07415610fb02a113c602a00610c428383401e7375627472616381005250fe7472616e736665726275726e20616d6f756e742065786365656473200062616c616e6365617070726f7665616c6c6f7766726f6d646563726561736500642062656c6f775061757361626c653a20746f6b656e7768696c652070617500736564a2646970667358221220e96342bec8f6c2bf72815a39998973b64c3b00ed57770f402e9a7b7eeda0265d4c64736f6c634300060c00331c5a77d9fa7e00f466951b2f01f724bca3a5820b63a0e012095745544820636f696e04c001a000235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c63310072a02f7c0384ddd06970446e74229cd96216da62196dc62395bda52095d44b008a9af7df0b80825dc0941a258d17bf244c4df02d40343a7626a9d321e105800080808080814aa8d130a9149a111111110549d2741105c418e61894eb01122000132dcb629c42c818e2c88850202223220549523307f06170f01bb60bc5a52b00d26b2c50bad4e2b2035c47a34038481f5c57890a393e7e010458ce81f09e490072a01121c9ac5b68d650819d732c48a37a11abde6747197969db3cb19efb34000e5599ae00e23d0c1e49e79382d1b7c50c62a112c690260d768f1c65149c24001c46f8708563b416f0f7a0dd98b6e0f685c551512e38ef2e20fe9f579ca4c6006146e0985928fbf8d1a3a8f3fac0c3a31ed348ff91848772604bcff17431fd0084da90ceacd54940452eea0ba22994bea2805624c107ee8ec4dec3a15897b000e2a6aa06fc4bd43eb964968fda4fd4ee7ee46d906ce01a8541022f5f0ab7da0067a5c348265c5652e06f484c92ff6d3158ec85cf1092226b8485c75ab799fc0012c9466daee43ce9132560a312094d536f7803541ca00845e3d84ea9b273c2004c15a17411e1331288b705778e3b7dc7830db1848b47113243da2e0d1012ba002a04a32898f050a8b61a02a7e6dc85eef13556ef249af7dd1d57508d3f7d2900af03f968d912ae39d330fcb9741b8010d4b0f0412f812401338eae5d10ef58001f23b0deea72f11e23aa1325a65d4d19e42222a0ef8b27aa7025bba4688c7900ccd826fa2c1ef64745e50f55e969672665104aed27e28c7adb52800be035d9003cf8163c31b92c81d7e14f7ab6ae1bf743b28fe7977924ce24fef45db39748001d0ce8628719fec729b5aa534c3df0e711d489ce2708547335ef2802fc757e00c3e7cb7b5bbf2ddd70d69a2ea5b9c345f34c9870d0a9f91cac0933a6a9b1e2005db9667ae51967d0165d126e7efc943894231266bafa034b808cd857a8972c00f5b2a95e79f52ec06822723b406fa7fe93a9fd522a9d5aa548c98ecc78d66b0084fd4f11a50c68c03b65c11af468801b23e9f1937dd4a5e9e38157d596e09a00526d4cda44f62b86afc0a88cfeb0e65aa8dd623c9174dce1044907ecc6b9b700837e720e198f2c60f3b0d946652c4e87c6324e1d5895b0beb72535e48e48f400180fbb8c40200e7ab8387fb224c9ef820e",
			expectedBlobVersionedHash: "0x012f5d0b0130addfce5502c7ce3d04945634fa80efd4b996ce71e1f2203ced3f",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03",
			batch: &Batch{
				Index:                  3,
				ParentBatchHash:        common.Hash{2},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.HexToHash("0x3d35d6b71c2769de1a4eb8f603e20f539c53a10c6764a6f5836cf13100000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			expectedBlobEncode:        "0007000c4d0160fd163d6200e49400003d35d6b71c2769de1a4eb8f603e20f53009c53a10c6764a6f5836cf1310002000363807b2a1de9000355418d1e8184000002646b6ed07a12000005000563807b2d1a2c0003546c3cbb39e500010000f8007180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0c00a28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf678100e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d0000c4d1996b9b5243c578fd7f51bfaec288bbaf42a8bf8710101bae6bf68e9a0003fb2bc0615b1bf0d69ce9411edf039985866d8256f10c1be4f7b2cace28d8f0020bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba68400835996fc3f879380aac1c09c6eed32f102f9162d82cf5502843b9b0a1783110097e28080b915d260806040523480156200001157600080fd5b5060405162000014b2380380833981810160405260a0811037815160208301516040808501800051915193959294830192918464018211639083019060208201858179825181001182820188101794825250918201929091019080838360005b83c357818101005183820152602001620000a9565b50505050905090810190601f16f1578082000380516001836020036101000a031916819150805160405193929190011501002b01460175015b01a39081015185519093508592508491620001c891600391008501906200026b565b508051620001de90600490602084506005805461ff00001960ff1990911660121716905550600680546001600160a01b0380881619920083161790925560078054928716929091169190911790556200023081620002005562010000600160b01b03191633021790555062000307915050565b60ff19001660ff929092565b828160011615610100020316600290049060005260206000002090601f016020900481019282601f10620002ae5780518380011785de010060010185558215620002de579182015b8202de5782518255916020019190600001c1565b50620002ec9291f0565b5090565b5b8002ec576000815560010162000002f1565b61119b80620003176000396000f3fe61001004361061010b576000003560e01c80635c975abb116100a257806395d89b411161007114610301570080639dc29fac14610309578063a457c2d714610335578063a9059cbb1461030061578063dd62ed3e1461038d5761010b565b1461029d57806370a0823114610002a55780638456cb59146102cb5780638e50817a146102d3313ce56711610000de571461021d578063395093511461023b5780633f4ba83a146102675780630040c10f191461027106fdde0314610110578063095ea7b31461018d5780631800160ddd146101cd57806323b872e7575b6101186103bb565b6040805160208000825283518183015283519192839290830161015261013a61017f9250508091000390f35b6101b9600480360360408110156101a381351690602001356104510091151582525190819003602001d561046e60fd81169160208101359091169000604074565b6102256104fb60ff90921640025105046f610552565b005b6102006f028705a956610654d520bb3516610662067d56e90135166106d21861075700031f07b856034b085f77c7d5a308db565b6003805420601f600260001961010000600188161502019095169490940493840181900481028201810190925282008152606093909290918301828280156104475780601f1061041c57610100800083540402835291610447565b825b8154815260200180831161042a5782900300601f16820191565b600061046561045e610906565b848461090a565b506001009202548184f6565b6104f18461048d6104ec8560405180606080602861108500602891398a166000908152600160205260408120906104cb81019190915260004001600020549190610b51565b935460ff160511016000610522908116825200602080830193909352604091820120918c168152925290205490610be8565b00600716331461059f5762461bcd60e51b60040b60248201526a1b9bdd08185b001b1bddd95960aa1b604482015290640190fd5b6105a7610c49565b61010090000460ff16156105f9106f14185d5cd8589b194e881c185d5cd9596082600606004606508282610ced909052604006ca0ddd900407260c6b6f6e6c792046616300746f727960a0079283918216179091559390921660041561080808550e6508006c2511176025006108968dd491824080832093909416825233831661094f5700040180806020018281038252602401806110f36024913960400191fd821661000994223d60228084166000819487168084529482529182902085905581518500815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b20000ac8c7c3b92592819003a3508316610a3b25ce8216610a80230ff86023610a008b838383610f61565b610ac881265f60268685808220939093559084168152002054610af7908220409490945580905191937fddf252ad1be2c89b69c2b06800fc378daa952ba7f163c4a11628f55a4df523b3ef929182900300818484111500610be08381815191508051900ba50b8d0bd2fd900300828201610c421b7f53006166654d6174683a206164646974696f6e206f766572666c6f7700610c9c140073621690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537b00d38aeae4b073aa610cd0a18216610d481f7f45524332303a206d696e742074006f20746865207a65726f72657373610d546000600254610d61025590205461000d8780838393519293910e2d6101001790557f62e78cea01bee320cd4e42020070b5ea74000d11b0c9f74754ebdbfc544b05a2588216610eaa6021ad602161000eb68260000ef3221b85839020550f199082610fb540805182600091851691009120565b610f6cb07415610fb02a113c602a00610c428383401e7375627472006163815250fe7472616e736665726275726e20616d6f756e742065786365650064732062616c616e6365617070726f7665616c6c6f7766726f6d646563726500617365642062656c6f775061757361626c653a20746f6b656e7768696c652000706175736564a2646970667358221220e96342bec8f6c2bf72815a3999897300b64c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c003300001c005a77d9fa7ef466951b2f01f724bca3a5820b63a0e012095745544820636f69006e04c001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e173700f0553c633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bd00a52095d44b8a9af7814aa8c130a9143223222222122449930e1105c418e6180094eb0112200329cb6220859031c49111a1404466440a92a4660ef06170a037000416b7372a8c6e8610e806c5190aca8c469770741f3857ad8a9c183f16023c00ce819dcea439088d90346b7d9a15a9c08c3943a5b9b68857ffb9a320bf34c2005c209c3b3e0ebd4cbf01f19e046f26314fc1c4b7112ef67e09034893e2368c001c51141c130ef37bb8ee31aa0bf8ecd36e18b420a265035131bd73402ec0fd009157a4a7c65bb6e198d950e6e8a34151b7f5518a472d6623dd20097c94a32200ddd1d39ffa49b6e106b38e3b0167b8883163a684f495285ad1013e6477ccfb001e8e635d765b325513f0d7a2d6889d5977d4e6a276f4239f46b2f9cd0006a100bc7c1e6e359fe80ea39fd8594965fd86ef24613116ebda5e580f2175b3665800e8af559a89410280a84d3fb92d7d4a10b0a244bf186a0b8f0065661efb681c009a2bf5344000a982942e227c46caf376d69d7b8edac418405c59f18089cc9100edf20642c6ad8a63943113fe16eaa48610a99975e1f9d79ac13b3f27f1eebe00e9b88fdf62b6d75b7f346f09d739533afcb9341a80c4d4f0f0d197408580b900c48d118b87591f466003d5e5626f8c7027764cc99a02c7454640df14cf555100f376fd420accb9c756f3b300b03f2595cda88abc9df93383f168df218ea8a3002d015c205e13c383b7e0919247101825fc43cf76b071975276fb0c378fe74c00023ebd85ec65a70e46ba3866863b774a49ed14bac7e759187ca07bb2cdcb5700938e8243b6e4eb7eeebd9f34d7d2ba6795e9c285bbbb689aa9130eb49b9c230068f2c6dc08d6e22bc4a7473f9322f6ef928de6074f3143d52401d1556b59c20066c44fa19eadd403a57aa2abd700a32dc96d007ae1fb0ff9b6ea5201df2ad5005f763ce3ad5e23307d8ad2659503262f0bbe412f032c1a49849f96a3d64d5f0004dc552d08ae29d5c6f84d64bc6a920b988a5119d8ab05a98bc77b97ce249c00d07440f0b8f53ce8e74e8a95cbb05c1f88fca60135d2d9b68c7c07922a2d11006c6f77bc58631eacad8402292db87611f103ccd5de4517",
			expectedBlobVersionedHash: "0x017407549060b08106683c1c986178635b49d8b82a6600a3a52ff1c147ba22a3",
		},
		// test error cases
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03, but with wrong (not consecutive) block number",
			batch: &Batch{
				Index:                  3,
				ParentBatchHash:        common.Hash{2},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), readBlockFromJSON(t, "testdata/blockTrace_05.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			creationErr: "invalid block number",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03, but with wrong PostL1MessageQueueHash",
			batch: &Batch{
				Index:                  3,
				ParentBatchHash:        common.Hash{2},
				PrevL1MessageQueueHash: common.Hash{1},
				PostL1MessageQueueHash: common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			creationErr: "failed to sanity check postL1MessageQueueHash",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02, 04 + 05 (L1 messages only), but with non-consecutive L1 messages number across blocks 04 and 05",
			batch: &Batch{
				Index:                  3,
				ParentBatchHash:        common.Hash{2},
				PrevL1MessageQueueHash: common.Hash{1},
				PostL1MessageQueueHash: common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 4)},
			},
			creationErr: "failed to sanity check L1 messages count",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02, 06, but with non-consecutive L1 messages number within block 06",
			batch: &Batch{
				Index:                  3,
				ParentBatchHash:        common.Hash{2},
				PrevL1MessageQueueHash: common.Hash{1},
				PostL1MessageQueueHash: common.HexToHash("0xfaa13a9ed8937474556dd2ea36be845199e823322cd63279a3ba300000000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_06.json"), 3)},
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

			require.Equal(t, tc.batch.PrevL1MessageQueueHash, blobPayload.PrevL1MessageQueueHash())
			require.Equal(t, tc.batch.PostL1MessageQueueHash, blobPayload.PostL1MessageQueueHash())

			// check correctness of decoded blocks and transactions
			require.Equal(t, len(tc.batch.Blocks), len(blobPayload.Blocks()))
			decodedBlocks := blobPayload.Blocks()
			for i, block := range tc.batch.Blocks {
				numL1Messages, _, _, err := block.NumL1MessagesNoSkipping()
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
	// We subtract 74 bytes for the blobPayloadV7 metadata.
	//compressableAvailableBytes := maxEffectiveBlobBytes*5 - 5 - blobPayloadV7MinEncodedLength
	maxAvailableBytesCompressable := 5*maxEffectiveBlobBytes - 5 - blobPayloadV7MinEncodedLength
	maxAvailableBytesIncompressable := maxEffectiveBlobBytes - 5 - blobPayloadV7MinEncodedLength
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
			expectedBlobVersionedHash: "0x018ea63fc2caaef749cedbeb0d890c006692a5507bb184817483bd5067e432b9",
		},
		{
			name:                      "single block, single tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x01982a2d4020291908a5370531ce3c4b011d3ee1bcf83219635d11f8a943395b",
		},
		{
			name:                      "single block, multiple tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x0178762564f254b45524a759b5a051315aa71bdd3479aa63733ad377e6ff711a",
		},
		{
			name:                      "multiple blocks, single tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x011efa14a395ed7bfdc20d501d60230a10ef88fda6988d22d7a67426ba0eb5a0",
		},
		{
			name:                      "multiple blocks, multiple tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01b9f4e80407f7a730235ae2268cdbf3cdb68b30adda6a557d2382f5777c73f3",
		},
		{
			name:                      "thousands of blocks, multiple tx per block",
			numBlocks:                 10000,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x010d6f1499e0ac277e9413f4e27f849ad0a57d9889dbd17a060c3000c4e50bd2",
		},
		{
			name:                      "single block, single tx, full blob random data -> data bigger compressed than uncompressed",
			numBlocks:                 1,
			txData:                    []string{generateRandomData(maxAvailableBytesIncompressable - bytesPerBlock)},
			expectedBlobVersionedHash: "0x01f201477ef7c9bd1e48f66ea60e6e0798dca8651900269f6e24b484587b821d",
		},
		{
			name:                      "2 blocks, single tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{generateRandomData(maxAvailableBytesIncompressable/2 - bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x017d7f0d569464b5c74175679e5f2bc880fcf5966c3e1928c9675c942b5274f0",
		},
		{
			name:                      "single block, single tx, full blob repeat data",
			numBlocks:                 1,
			txData:                    []string{repeat(0x12, maxAvailableBytesCompressable-bytesPerBlock)},
			expectedBlobVersionedHash: "0x01f5d7bbfe7deb429bcbdd7347606359bca75cb93b9198e8f089b82e45f92b43",
		},
		{
			name:                      "2 blocks, single 2, full blob random data",
			numBlocks:                 2,
			txData:                    []string{repeat(0x12, maxAvailableBytesCompressable/2-bytesPerBlock*2), repeat(0x13, maxAvailableBytesCompressable/2-bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01dccca3859640c50e0058fd42eaf14f942070e6497a4e2ba507b4546280a772",
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
	// We subtract 74 bytes for the blobPayloadV7 metadata.
	maxAvailableBytes := maxEffectiveBlobBytes - 5 - blobPayloadV7MinEncodedLength
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
			expectedBlobVersionedHash: "0x0127467f5062c887d10c72713d76406ef5caebe2df5b1b679a1b5cd812cf395b",
		},
		{
			name:                      "single block, single tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x01752838099db7811eea826eaf2c4a2ea2ffd832fb4e4e981243112a6e94f3ce",
		},
		{
			name:                      "single block, multiple tx",
			numBlocks:                 1,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01d242d36f0dea017320aa36dcc565d0a11708c9521f95027bd59813b1a455ec",
		},
		{
			name:                      "multiple blocks, single tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203"},
			expectedBlobVersionedHash: "0x015e10ec939109061216dd6cf61551eb443a3e75ef43d97334c5b2ee52c47148",
		},
		{
			name:                      "multiple blocks, multiple tx per block",
			numBlocks:                 3,
			txData:                    []string{"0x010203", "0x040506", "0x070809"},
			expectedBlobVersionedHash: "0x01877eaa8ef364fca0ab2df8b1b30435228436ef6e34ee5abefed2a8de384a78",
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
			expectedBlobVersionedHash: "0x01f201477ef7c9bd1e48f66ea60e6e0798dca8651900269f6e24b484587b821d",
		},
		{
			name:                      "2 blocks, single tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{generateRandomData(maxAvailableBytes/2 - bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01ae4b29190bcbb86e9b0100cd456e4119a3eb991bd8c7215d6f7471883290a2",
		},
		{
			name:                      "single block, single tx, full blob repeat data",
			numBlocks:                 1,
			txData:                    []string{repeat(0x12, maxAvailableBytes-bytesPerBlock)},
			expectedBlobVersionedHash: "0x011e1d9e8f14453d4b2a73edcd962d4ccaf54580069bc636c59de87a80800a2f",
		},
		{
			name:                      "2 blocks, 2 tx, full blob random data",
			numBlocks:                 2,
			txData:                    []string{repeat(0x12, maxAvailableBytes/4-bytesPerBlock*2), repeat(0x13, maxAvailableBytes/4-bytesPerBlock*2)},
			expectedBlobVersionedHash: "0x01148a71a69e6d2d00562397d2e1938dc2634f153a6ee37122bfd70cff676aaf",
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
				PostL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_04.json")},
			},
			expectCompatible: true,
		},
		{
			name: "Single Block 05, only L1 messages",
			batch: &Batch{
				PostL1MessageQueueHash: common.HexToHash("0x3d35d6b71c2769de1a4eb8f603e20f539c53a10c6764a6f5836cf13100000000"),
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
				PostL1MessageQueueHash: common.HexToHash("0xc7436aaec2cfaf39d5be02a02c6ac2089ab264c3e0fd142db682f1cc00000000"),
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

func TestCodecV7BatchBlobDataProofForPointEvaluation(t *testing.T) {
	testCases := []struct {
		name                  string
		batch                 *Batch
		creationErr           string
		expectedBlobDataProof string
	}{
		{
			name: "Batch with 1 block, blocktrace 02",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.Hash{},
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json")},
			},
			expectedBlobDataProof: "0a8939c8acbd2bc2fb3ffd61624e55ebe6d0e000958d7505df6863c4062438414cf197faff537d1549b333f4f5d28a1f26123b723c316862e0f285193accead8949b925113ca4f9a8de59f234af023e4da3892e02dd786092699f15bdce7f3be248a075a1f40d82b86e65895b38693b68b08960479a11237c6699777fc97cf53c10f6503a6a8c0ad8eb35b68d6b051506b20ea3a8f41c3058a366c71fb7c1790",
		},
		{
			name: "Batch with 1 block, blocktrace 03",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.Hash{},
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_03.json")},
			},
			expectedBlobDataProof: "05a0e06b0cc573a726a3a3a48ee7b7014480968bd4ec9848effb7d0af33d4127589fc8cc458c673e174455d68d2c2c31847ad09b8805deb61cbef48505a34d88841ff44ffeeb9dc073ef133be9a34cc796babdfbd2f4d5785faf18b96558918e1fe5193d78e2611acf4671888a01a0fc89dde18bef6ab54c7af95df8e3016f0c930ca5f4967de08c6b20c52005acf1dc248eace2ff0a98a89c840bfe15b1594e",
		},
		{
			name: "Batch with 1 block, blocktrace 04",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{1, 2, 3, 4},
				PrevL1MessageQueueHash: common.Hash{1, 2, 3, 4},
				PostL1MessageQueueHash: common.HexToHash("0x6250cf03e7f922eefe450e9d4234ec56a1502066cd55eff22939df6100000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_04.json")},
			},
			expectedBlobDataProof: "1c8917a0f90db3a2370fd18528d1cc9146340ef5cab7511786e212685c0ecfb656d871474ea7fd56a454b4042222240bf4b2fa15ab651cf0cd0b2bed9a9c9271ab3f7d6468190f56f55aca9802683ee6b9cada6fead43bb3cedbb132bcf08a27fcff326a0bb8599a89a57facbbcb49f5a8fa213e77c56332f996e020fed17cf2e607d015b997a9ad1cb993efff674cd8810c00a7539a771feb6fb5b2d41c2512",
		},
		{
			name: "Batch with 1 block, blocktrace 05",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{5, 6, 7, 8},
				PostL1MessageQueueHash: common.HexToHash("0xc31c3ca9a880b80c4e7fcb88844a5e21433bd2801bdd504e1ca4aed900000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_05.json")},
			},
			expectedBlobDataProof: "21c2fc4f348de240738bec7591ef72586db52feb7fca79f4d86c87e2b68efa9f1a3bf56b3991eb2e31347054ff227759779acec5ff78c3285c4abb09f2e785bd8d724b0c40745df1e30d6609899b63d88015110bd0f7ca4c9bee0dda327f8ce038e8d0b1179838086799d3c33ce31766afcf23fb52de7757c16a7766f2dc20179d832614bb070431ad5b90fe5b393d34423bf3291373b6072e05c46bc519a752",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 03 + 04",
			batch: &Batch{
				Index:                  1,
				ParentBatchHash:        common.Hash{},
				PrevL1MessageQueueHash: common.Hash{9, 10, 11},
				PostL1MessageQueueHash: common.HexToHash("0x20f1c72064552d63fb7e1352b7815a9f8231a028220bf63d27b24bec00000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), readBlockFromJSON(t, "testdata/blockTrace_03.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_04.json"), 4)},
			},
			expectedBlobDataProof: "0b2f1a222f892d9114f3218ce3e5d1a7ba5f043960eff378250e1fa8d649bd076f7ff992b3f030a568543585a9d20bd8ede981dc6901ece26e273b1217da07f4852da1ea424859a212ac35d7d2262ca380c4bc017b20a01b00786a580916b48e763e3ae5c59eeac4d121db442efc7763b3dca263a31bdb7f27ab0a59e8d80566120c8a8d92e4b22efeed5b1863349da44c5103b1420c45598a74cd7cc8d788df",
		},
		{
			name: "Batch with 3 blocks, blocktrace 02 + 05 (L1 messages only) + 03",
			batch: &Batch{
				Index:                  3,
				ParentBatchHash:        common.Hash{2},
				PrevL1MessageQueueHash: common.Hash{},
				PostL1MessageQueueHash: common.HexToHash("0x3d35d6b71c2769de1a4eb8f603e20f539c53a10c6764a6f5836cf13100000000"),
				Blocks:                 []*Block{readBlockFromJSON(t, "testdata/blockTrace_02.json"), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_05.json"), 3), replaceBlockNumber(readBlockFromJSON(t, "testdata/blockTrace_03.json"), 4)},
			},
			expectedBlobDataProof: "04ca4fb500d52948a622671911cdfc4856b5d169a0a0aed5ff19dc2be2a4eb7f4665316bafd3bf33b8e1df624dbfbb1df762aa65a41c880d38b4e7d734a098c6a3e23c97184774ae69247dbec30060787f1ba97472bb41184b768d9180e860fc4ee91770a4236f224f01dcffb443c259a273b07de848a5db106f6fa7558e26011637c0851e047db4f12c26132d8a0355a3745f34b53ceadb6eb5f368d9ddfef0",
		},
	}

	codecV7, err := CodecFromVersion(CodecV7)
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			daBatch, err := codecV7.NewDABatch(tc.batch)
			require.NoError(t, err)
			verifyData, err := daBatch.BlobDataProofForPointEvaluation()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedBlobDataProof, hex.EncodeToString(verifyData))
		})
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
