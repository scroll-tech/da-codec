package encoding

import (
	"encoding/hex"
	"testing"

	"github.com/scroll-tech/go-ethereum/common"
	"github.com/scroll-tech/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func TestCodecV0BlockEncode(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	block := &daBlockV0{}
	encoded := hex.EncodeToString(block.Encode())
	assert.Equal(t, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	daBlock, err := codecv0.NewDABlock(block2, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e818400020000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	daBlock, err = codecv0.NewDABlock(block3, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "00000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e500010000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	daBlock, err = codecv0.NewDABlock(block4, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	daBlock, err = codecv0.NewDABlock(block5, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	daBlock, err = codecv0.NewDABlock(block6, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	daBlock, err = codecv0.NewDABlock(block7, 0)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBlock.Encode())
	assert.Equal(t, "000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)
}

func TestCodecV0ChunkEncode(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	// chunk with a single empty block
	daBlock := &daBlockV0{}
	daChunkV0 := &daChunkV0{blocks: []DABlock{daBlock}, transactions: [][]*types.TransactionData{nil}}

	encodedBytes, err := daChunkV0.Encode()
	assert.NoError(t, err)
	encoded := hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	originalChunk := &Chunk{Blocks: []*Block{block}}
	daChunk, err := codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000020000000063807b2a0000000000000000000000000000000000000000000000000000000000001de9000355418d1e81840002000000000073f87180843b9aec2e8307a12094c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca28a152d02c7e14af60000008083019ecea0ab07ae99c67aa78e7ba5cf6781e90cc32b219b1de102513d56548a41e86df514a034cbd19feacd73e8ce64d00c4d1996b9b5243c578fd7f51bfaec288bbaf42a8b00000073f87101843b9aec2e8307a1209401bae6bf68e9a03fb2bc0615b1bf0d69ce9411ed8a152d02c7e14af60000008083019ecea0f039985866d8256f10c1be4f7b2cace28d8f20bde27e2604393eb095b7f77316a05a3e6e81065f2b4604bcec5bd4aba684835996fc3f879380aac1c09c6eed32f1", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "0100000000000000030000000063807b2d0000000000000000000000000000000000000000000000000000000000001a2c0003546c3cbb39e5000100000000163102f9162d82cf5502843b9b0a17843b9b0a17831197e28080b915d260806040523480156200001157600080fd5b50604051620014b2380380620014b2833981810160405260a08110156200003757600080fd5b815160208301516040808501805191519395929483019291846401000000008211156200006357600080fd5b9083019060208201858111156200007957600080fd5b82516401000000008111828201881017156200009457600080fd5b82525081516020918201929091019080838360005b83811015620000c3578181015183820152602001620000a9565b50505050905090810190601f168015620000f15780820380516001836020036101000a031916815260200191505b50604052602001805160405193929190846401000000008211156200011557600080fd5b9083019060208201858111156200012b57600080fd5b82516401000000008111828201881017156200014657600080fd5b82525081516020918201929091019080838360005b83811015620001755781810151838201526020016200015b565b50505050905090810190601f168015620001a35780820380516001836020036101000a031916815260200191505b5060405260209081015185519093508592508491620001c8916003918501906200026b565b508051620001de9060049060208401906200026b565b50506005805461ff001960ff1990911660121716905550600680546001600160a01b038088166001600160a01b0319928316179092556007805492871692909116919091179055620002308162000255565b50506005805462010000600160b01b0319163362010000021790555062000307915050565b6005805460ff191660ff92909216919091179055565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f10620002ae57805160ff1916838001178555620002de565b82800160010185558215620002de579182015b82811115620002de578251825591602001919060010190620002c1565b50620002ec929150620002f0565b5090565b5b80821115620002ec5760008155600101620002f1565b61119b80620003176000396000f3fe608060405234801561001057600080fd5b506004361061010b5760003560e01c80635c975abb116100a257806395d89b411161007157806395d89b41146103015780639dc29fac14610309578063a457c2d714610335578063a9059cbb14610361578063dd62ed3e1461038d5761010b565b80635c975abb1461029d57806370a08231146102a55780638456cb59146102cb5780638e50817a146102d35761010b565b8063313ce567116100de578063313ce5671461021d578063395093511461023b5780633f4ba83a1461026757806340c10f19146102715761010b565b806306fdde0314610110578063095ea7b31461018d57806318160ddd146101cd57806323b872dd146101e7575b600080fd5b6101186103bb565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561015257818101518382015260200161013a565b50505050905090810190601f16801561017f5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101b9600480360360408110156101a357600080fd5b506001600160a01b038135169060200135610451565b604080519115158252519081900360200190f35b6101d561046e565b60408051918252519081900360200190f35b6101b9600480360360608110156101fd57600080fd5b506001600160a01b03813581169160208101359091169060400135610474565b6102256104fb565b6040805160ff9092168252519081900360200190f35b6101b96004803603604081101561025157600080fd5b506001600160a01b038135169060200135610504565b61026f610552565b005b61026f6004803603604081101561028757600080fd5b506001600160a01b0381351690602001356105a9565b6101b9610654565b6101d5600480360360208110156102bb57600080fd5b50356001600160a01b0316610662565b61026f61067d565b61026f600480360360408110156102e957600080fd5b506001600160a01b03813581169160200135166106d2565b610118610757565b61026f6004803603604081101561031f57600080fd5b506001600160a01b0381351690602001356107b8565b6101b96004803603604081101561034b57600080fd5b506001600160a01b03813516906020013561085f565b6101b96004803603604081101561037757600080fd5b506001600160a01b0381351690602001356108c7565b6101d5600480360360408110156103a357600080fd5b506001600160a01b03813581169160200135166108db565b60038054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156104475780601f1061041c57610100808354040283529160200191610447565b820191906000526020600020905b81548152906001019060200180831161042a57829003601f168201915b5050505050905090565b600061046561045e610906565b848461090a565b50600192915050565b60025490565b60006104818484846109f6565b6104f18461048d610906565b6104ec85604051806060016040528060288152602001611085602891396001600160a01b038a166000908152600160205260408120906104cb610906565b6001600160a01b031681526020810191909152604001600020549190610b51565b61090a565b5060019392505050565b60055460ff1690565b6000610465610511610906565b846104ec8560016000610522610906565b6001600160a01b03908116825260208083019390935260409182016000908120918c168152925290205490610be8565b6007546001600160a01b0316331461059f576040805162461bcd60e51b815260206004820152600b60248201526a1b9bdd08185b1b1bddd95960aa1b604482015290519081900360640190fd5b6105a7610c49565b565b600554610100900460ff16156105f9576040805162461bcd60e51b815260206004820152601060248201526f14185d5cd8589b194e881c185d5cd95960821b604482015290519081900360640190fd5b6006546001600160a01b03163314610646576040805162461bcd60e51b815260206004820152600b60248201526a1b9bdd08185b1b1bddd95960aa1b604482015290519081900360640190fd5b6106508282610ced565b5050565b600554610100900460ff1690565b6001600160a01b031660009081526020819052604090205490565b6007546001600160a01b031633146106ca576040805162461bcd60e51b815260206004820152600b60248201526a1b9bdd08185b1b1bddd95960aa1b604482015290519081900360640190fd5b6105a7610ddd565b6005546201000090046001600160a01b03163314610726576040805162461bcd60e51b815260206004820152600c60248201526b6f6e6c7920466163746f727960a01b604482015290519081900360640190fd5b600780546001600160a01b039283166001600160a01b03199182161790915560068054939092169216919091179055565b60048054604080516020601f60026000196101006001881615020190951694909404938401819004810282018101909252828152606093909290918301828280156104475780601f1061041c57610100808354040283529160200191610447565b600554610100900460ff1615610808576040805162461bcd60e51b815260206004820152601060248201526f14185d5cd8589b194e881c185d5cd95960821b604482015290519081900360640190fd5b6006546001600160a01b03163314610855576040805162461bcd60e51b815260206004820152600b60248201526a1b9bdd08185b1b1bddd95960aa1b604482015290519081900360640190fd5b6106508282610e65565b600061046561086c610906565b846104ec856040518060600160405280602581526020016111176025913960016000610896610906565b6001600160a01b03908116825260208083019390935260409182016000908120918d16815292529020549190610b51565b60006104656108d4610906565b84846109f6565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b3390565b6001600160a01b03831661094f5760405162461bcd60e51b81526004018080602001828103825260248152602001806110f36024913960400191505060405180910390fd5b6001600160a01b0382166109945760405162461bcd60e51b815260040180806020018281038252602281526020018061103d6022913960400191505060405180910390fd5b6001600160a01b03808416600081815260016020908152604080832094871680845294825291829020859055815185815291517f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9259281900390910190a3505050565b6001600160a01b038316610a3b5760405162461bcd60e51b81526004018080602001828103825260258152602001806110ce6025913960400191505060405180910390fd5b6001600160a01b038216610a805760405162461bcd60e51b8152600401808060200182810382526023815260200180610ff86023913960400191505060405180910390fd5b610a8b838383610f61565b610ac88160405180606001604052806026815260200161105f602691396001600160a01b0386166000908152602081905260409020549190610b51565b6001600160a01b038085166000908152602081905260408082209390935590841681522054610af79082610be8565b6001600160a01b038084166000818152602081815260409182902094909455805185815290519193928716927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a3505050565b60008184841115610be05760405162461bcd60e51b81526004018080602001828103825283818151815260200191508051906020019080838360005b83811015610ba5578181015183820152602001610b8d565b50505050905090810190601f168015610bd25780820380516001836020036101000a031916815260200191505b509250505060405180910390fd5b505050900390565b600082820183811015610c42576040805162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b9392505050565b600554610100900460ff16610c9c576040805162461bcd60e51b815260206004820152601460248201527314185d5cd8589b194e881b9bdd081c185d5cd95960621b604482015290519081900360640190fd5b6005805461ff00191690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa610cd0610906565b604080516001600160a01b039092168252519081900360200190a1565b6001600160a01b038216610d48576040805162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015290519081900360640190fd5b610d5460008383610f61565b600254610d619082610be8565b6002556001600160a01b038216600090815260208190526040902054610d879082610be8565b6001600160a01b0383166000818152602081815260408083209490945583518581529351929391927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a35050565b600554610100900460ff1615610e2d576040805162461bcd60e51b815260206004820152601060248201526f14185d5cd8589b194e881c185d5cd95960821b604482015290519081900360640190fd5b6005805461ff0019166101001790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258610cd0610906565b6001600160a01b038216610eaa5760405162461bcd60e51b81526004018080602001828103825260218152602001806110ad6021913960400191505060405180910390fd5b610eb682600083610f61565b610ef38160405180606001604052806022815260200161101b602291396001600160a01b0385166000908152602081905260409020549190610b51565b6001600160a01b038316600090815260208190526040902055600254610f199082610fb5565b6002556040805182815290516000916001600160a01b038516917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9181900360200190a35050565b610f6c838383610fb0565b610f74610654565b15610fb05760405162461bcd60e51b815260040180806020018281038252602a81526020018061113c602a913960400191505060405180910390fd5b505050565b6000610c4283836040518060400160405280601e81526020017f536166654d6174683a207375627472616374696f6e206f766572666c6f770000815250610b5156fe45524332303a207472616e7366657220746f20746865207a65726f206164647265737345524332303a206275726e20616d6f756e7420657863656564732062616c616e636545524332303a20617070726f766520746f20746865207a65726f206164647265737345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e636545524332303a207472616e7366657220616d6f756e74206578636565647320616c6c6f77616e636545524332303a206275726e2066726f6d20746865207a65726f206164647265737345524332303a207472616e736665722066726f6d20746865207a65726f206164647265737345524332303a20617070726f76652066726f6d20746865207a65726f206164647265737345524332303a2064656372656173656420616c6c6f77616e63652062656c6f77207a65726f45524332305061757361626c653a20746f6b656e207472616e73666572207768696c6520706175736564a2646970667358221220e96342bec8f6c2bf72815a39998973b64c3bed57770f402e9a7b7eeda0265d4c64736f6c634300060c00330000000000000000000000001c5a77d9fa7ef466951b2f01f724bca3a5820b630000000000000000000000001c5a77d9fa7ef466951b2f01f724bca3a5820b6300000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000095745544820636f696e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045745544800000000000000000000000000000000000000000000000000000000c001a0235c1a8d40e8c347890397f1a92e6eadbd6422cf7c210e3e1737f0553c633172a02f7c0384ddd06970446e74229cd96216da62196dc62395bda52095d44b8a9af7", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000000d00000000646b6e13000000000000000000000000000000000000000000000000000000000000000000000000007a1200000c000b00000020df0b80825dc0941a258d17bf244c4df02d40343a7626a9d321e1058080808080", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200002a002a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a1200000a000a", encoded)

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	encodedBytes, err = daChunk.Encode()
	assert.NoError(t, err)
	encoded = hex.EncodeToString(encodedBytes)
	assert.Equal(t, "01000000000000001100000000646b6ed0000000000000000000000000000000000000000000000000000000000000000000000000007a120001010101", encoded)
}

func TestCodecV0ChunkHash(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	// chunk with a single empty block
	daBlock := &daBlockV0{}
	chunk := &daChunkV0{blocks: []DABlock{daBlock}, transactions: [][]*types.TransactionData{nil}}
	hash, err := chunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x7cdb9d7f02ea58dfeb797ed6b4f7ea68846e4f2b0e30ed1535fc98b60c4ec809", hash.Hex())

	// invalid hash
	chunk.transactions[0] = append(chunk.transactions[0], &types.TransactionData{Type: types.L1MessageTxType, TxHash: "0xg"})
	_, err = chunk.Hash()
	assert.Error(t, err)

	block := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	originalChunk := &Chunk{Blocks: []*Block{block}}
	daChunk, err := codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xde642c68122634b33fa1e6e4243b17be3bfd0dc6f996f204ef6d7522516bd840", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_03.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xde29f4371cc396b2e7c536cdc7a7c20ac5c728cbb8af3247074c746ff452632b", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_04.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x9e643c8a9203df542e39d9bfdcb07c99575b3c3d557791329fef9d83cc4147d0", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_05.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x854fc3136f47ce482ec85ee3325adfa16a1a1d60126e1c119eaaf0c3a9e90f8e", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_06.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0x2aa220ca7bd1368e59e8053eb3831e30854aa2ec8bd3af65cee350c1c0718ba6", hash.Hex())

	block = readBlockFromJSON(t, "testdata/blockTrace_07.json")
	originalChunk = &Chunk{Blocks: []*Block{block}}
	daChunk, err = codecv0.NewDAChunk(originalChunk, 0)
	assert.NoError(t, err)
	hash, err = daChunk.Hash()
	assert.NoError(t, err)
	assert.Equal(t, "0xb65521bea7daff75838de07951c3c055966750fb5a270fead5e0e727c32455c3", hash.Hex())
}

func TestCodecV0BatchEncode(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	// empty batch
	batch := &daBatchV1{
		daBatchV0: daBatchV0{
			version: uint8(CodecV0),
		},
	}
	encoded := hex.EncodeToString(batch.Encode())
	assert.Equal(t, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", encoded)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "000000000000000000000000000000000000000000000000008fbc5eecfefc5bd9d1618ecef1fed160a7838448383595a2257d4c9bd5c5fa3e0000000000000000000000000000000000000000000000000000000000000000", encoded)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "0000000000000000000000000000000000000000000000000019d1fad630fcc61bd49949fa01e58d198f67a58f1c4aea43f32714ceaa9e0e760000000000000000000000000000000000000000000000000000000000000000", encoded)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "000000000000000000000000000000000b000000000000000b34f419ce7e882295bdb5aec6cce56ffa788a5fed4744d7fbd77e4acbf409f1ca000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ff", encoded)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "000000000000000000000000000000002a000000000000002a93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fffffffff", encoded)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "000000000000000000000000000000000a000000000000000ac7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001dd", encoded)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "00000000000000000000000000000001010000000000000101899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d52080000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0000000000000000000000000000000000000000000000000000000000000000", encoded)

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "000000000000000000000000000000002a000000000000002a908c20b6255fd8cd8fb3a7995e9980007ebedcfe359cee2d8e899aefe319836e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	encoded = hex.EncodeToString(daBatch.Encode())
	assert.Equal(t, "000000000000000000000000000000002a000000000000002a1f9b3d942a6ee14e7afc52225c91fa44faa0a7ec511df9a2d9348d33bcd142fc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ffffffbff", encoded)
}

func TestCodecV0BatchHash(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	// empty batch
	batch := &daBatchV1{
		daBatchV0: daBatchV0{
			version: uint8(CodecV0),
		},
	}
	assert.Equal(t, common.HexToHash("0x7f74e58579672e582998264e7e8191c51b6b8981afd0f9bf1a2ffc3abb39e678"), batch.Hash())

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x4605465b7470c8565b123330d7186805caf9a7f2656d8e9e744b62e14ca22c3d"), daBatch.Hash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x922e004553d563bde6560a827c6449200bfd84f92917dfa14d740f26e52c59bc"), daBatch.Hash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xfbb081f25d6d06aefd76f062eee50885faf5bb050c8f31d533fc8560e655b690"), daBatch.Hash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x99f9648e4d090f1222280bec95a3f1e39c6cbcd4bff21eb2ae94b1536bb23acc"), daBatch.Hash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xe0950d500d47df4e9c443978682bcccfc8d50983f99ec9232067333a7d32a9d2"), daBatch.Hash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x745a74773cdc7cd0b86b50305f6373c7efeaf051b38a71ea561333708e8a90d9"), daBatch.Hash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x85b5c152c5c0b25731bfab6f4d309e94a42ddf0f4c9235189e5cd19c5c008522"), daBatch.Hash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc5e787fa6a83374135c3b95bd8325bcc0440cd5eb2d71bb31ddca67dd2d44f64"), daBatch.Hash())
}

func TestCodecV0BatchDataHash(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x8fbc5eecfefc5bd9d1618ecef1fed160a7838448383595a2257d4c9bd5c5fa3e"), daBatch.DataHash())

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x19d1fad630fcc61bd49949fa01e58d198f67a58f1c4aea43f32714ceaa9e0e76"), daBatch.DataHash())

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x34f419ce7e882295bdb5aec6cce56ffa788a5fed4744d7fbd77e4acbf409f1ca"), daBatch.DataHash())

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x93255aa24dd468c5645f1e6901b8131a7a78a0eeb2a17cbb09ba64688a8de6b4"), daBatch.DataHash())

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0xc7bcc8da943dd83404e84d9ce7e894ab97ce4829df4eb51ebbbe13c90b5a3f4d"), daBatch.DataHash())

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x899a411a3309c6491701b7b955c7b1115ac015414bbb71b59a0ca561668d5208"), daBatch.DataHash())

	originalBatch = &Batch{Chunks: []*Chunk{chunk2, chunk3, chunk4, chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x908c20b6255fd8cd8fb3a7995e9980007ebedcfe359cee2d8e899aefe319836e"), daBatch.DataHash())

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}}
	chunk9 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToHash("0x1f9b3d942a6ee14e7afc52225c91fa44faa0a7ec511df9a2d9348d33bcd142fc"), daBatch.DataHash())
}

func TestCodecV0CalldataSizeEstimation(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2CalldataSize, err := codecv0.EstimateChunkL1CommitCalldataSize(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(298), chunk2CalldataSize)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2CalldataSize, err := codecv0.EstimateBatchL1CommitCalldataSize(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(298), batch2CalldataSize)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3CalldataSize, err := codecv0.EstimateChunkL1CommitCalldataSize(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5745), chunk3CalldataSize)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3CalldataSize, err := codecv0.EstimateBatchL1CommitCalldataSize(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5745), batch3CalldataSize)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4CalldataSize, err := codecv0.EstimateChunkL1CommitCalldataSize(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(96), chunk4CalldataSize)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4CalldataSize, err := codecv0.EstimateBatchL1CommitCalldataSize(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(96), batch4CalldataSize)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5CalldataSize, err := codecv0.EstimateChunkL1CommitCalldataSize(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6043), chunk5CalldataSize)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6CalldataSize, err := codecv0.EstimateChunkL1CommitCalldataSize(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(96), chunk6CalldataSize)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5CalldataSize, err := codecv0.EstimateBatchL1CommitCalldataSize(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(6139), batch5CalldataSize)
}

func TestCodecV0CommitGasEstimation(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	assert.NoError(t, err)
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	chunk2Gas, err := codecv0.EstimateChunkL1CommitGas(chunk2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5082), chunk2Gas)
	batch2 := &Batch{Chunks: []*Chunk{chunk2}}
	batch2Gas, err := codecv0.EstimateBatchL1CommitGas(batch2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(161631), batch2Gas)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	chunk3Gas, err := codecv0.EstimateChunkL1CommitGas(chunk3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(93786), chunk3Gas)
	batch3 := &Batch{Chunks: []*Chunk{chunk3}}
	batch3Gas, err := codecv0.EstimateBatchL1CommitGas(batch3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(250908), batch3Gas)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	chunk4Gas, err := codecv0.EstimateChunkL1CommitGas(chunk4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(4369), chunk4Gas)
	batch4 := &Batch{Chunks: []*Chunk{chunk4}}
	batch4Gas, err := codecv0.EstimateBatchL1CommitGas(batch4)
	assert.NoError(t, err)
	assert.Equal(t, uint64(160929), batch4Gas)

	chunk5 := &Chunk{Blocks: []*Block{block2, block3}}
	chunk5Gas, err := codecv0.EstimateChunkL1CommitGas(chunk5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(98822), chunk5Gas)
	chunk6 := &Chunk{Blocks: []*Block{block4}}
	chunk6Gas, err := codecv0.EstimateChunkL1CommitGas(chunk6)
	assert.NoError(t, err)
	assert.Equal(t, uint64(4369), chunk6Gas)
	batch5 := &Batch{Chunks: []*Chunk{chunk5, chunk6}}
	batch5Gas, err := codecv0.EstimateBatchL1CommitGas(batch5)
	assert.NoError(t, err)
	assert.Equal(t, uint64(260958), batch5Gas)
}

func TestCodecV0BatchL1MessagePopped(t *testing.T) {
	codecv0, err := CodecFromVersion(CodecV0)
	assert.NoError(t, err)

	block2 := readBlockFromJSON(t, "testdata/blockTrace_02.json")
	chunk2 := &Chunk{Blocks: []*Block{block2}}
	originalBatch := &Batch{Chunks: []*Chunk{chunk2}}
	daBatch, err := codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV0).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV0).totalL1MessagePopped)

	block3 := readBlockFromJSON(t, "testdata/blockTrace_03.json")
	chunk3 := &Chunk{Blocks: []*Block{block3}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk3}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV0).l1MessagePopped)
	assert.Equal(t, uint64(0), daBatch.(*daBatchV0).totalL1MessagePopped)

	block4 := readBlockFromJSON(t, "testdata/blockTrace_04.json")
	chunk4 := &Chunk{Blocks: []*Block{block4}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk4}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV0).l1MessagePopped)
	assert.Equal(t, uint64(11), daBatch.(*daBatchV0).totalL1MessagePopped)

	block5 := readBlockFromJSON(t, "testdata/blockTrace_05.json")
	chunk5 := &Chunk{Blocks: []*Block{block5}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk5}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV0).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV0).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 37
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(5), daBatch.(*daBatchV0).l1MessagePopped) // skip 37, include 5
	assert.Equal(t, uint64(42), daBatch.(*daBatchV0).totalL1MessagePopped)

	block6 := readBlockFromJSON(t, "testdata/blockTrace_06.json")
	chunk6 := &Chunk{Blocks: []*Block{block6}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk6}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(10), daBatch.(*daBatchV0).l1MessagePopped) // skip 7, include 3
	assert.Equal(t, uint64(10), daBatch.(*daBatchV0).totalL1MessagePopped)

	block7 := readBlockFromJSON(t, "testdata/blockTrace_07.json")
	chunk7 := &Chunk{Blocks: []*Block{block7}}
	originalBatch = &Batch{Chunks: []*Chunk{chunk7}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(257), daBatch.(*daBatchV0).l1MessagePopped) // skip 255, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV0).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 1
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(256), daBatch.(*daBatchV0).l1MessagePopped) // skip 254, include 2
	assert.Equal(t, uint64(257), daBatch.(*daBatchV0).totalL1MessagePopped)

	chunk8 := &Chunk{Blocks: []*Block{block2, block3, block4}} // queue index 10
	chunk9 := &Chunk{Blocks: []*Block{block5}}                 // queue index 37-41
	originalBatch = &Batch{Chunks: []*Chunk{chunk8, chunk9}}
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV0).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV0).totalL1MessagePopped)

	originalBatch.TotalL1MessagePoppedBefore = 10
	daBatch, err = codecv0.NewDABatch(originalBatch)
	assert.NoError(t, err)
	assert.Equal(t, uint64(32), daBatch.(*daBatchV0).l1MessagePopped)
	assert.Equal(t, uint64(42), daBatch.(*daBatchV0).totalL1MessagePopped)
}
