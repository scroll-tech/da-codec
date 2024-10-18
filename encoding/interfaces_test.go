package encoding

import (
	"math/big"
	"testing"

	"github.com/scroll-tech/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

func TestCodecFromVersion(t *testing.T) {
	tests := []struct {
		name    string
		version CodecVersion
		want    Codec
		wantErr bool
	}{
		{"CodecV0", CodecV0, &DACodecV0{}, false},
		{"CodecV1", CodecV1, &DACodecV1{}, false},
		{"CodecV2", CodecV2, &DACodecV2{}, false},
		{"CodecV3", CodecV3, &DACodecV3{}, false},
		{"CodecV4", CodecV4, &DACodecV4{}, false},
		{"InvalidCodec", CodecVersion(99), nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CodecFromVersion(tt.version)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.IsType(t, tt.want, got)
			}
		})
	}
}

func TestCodecFromConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *params.ChainConfig
		blockNum  *big.Int
		timestamp uint64
		want      Codec
	}{
		{
			name: "DarwinV2 active",
			config: &params.ChainConfig{
				LondonBlock:    big.NewInt(0),
				BernoulliBlock: big.NewInt(0),
				CurieBlock:     big.NewInt(0),
				DarwinTime:     new(uint64),
				DarwinV2Time:   new(uint64),
			},
			blockNum:  big.NewInt(0),
			timestamp: 0,
			want:      &DACodecV4{},
		},
		{
			name: "Darwin active",
			config: &params.ChainConfig{
				LondonBlock:    big.NewInt(0),
				BernoulliBlock: big.NewInt(0),
				CurieBlock:     big.NewInt(0),
				DarwinTime:     new(uint64),
			},
			blockNum:  big.NewInt(0),
			timestamp: 0,
			want:      &DACodecV3{},
		},
		{
			name: "Curie active",
			config: &params.ChainConfig{
				LondonBlock:    big.NewInt(0),
				BernoulliBlock: big.NewInt(0),
				CurieBlock:     big.NewInt(0),
			},
			blockNum:  big.NewInt(0),
			timestamp: 0,
			want:      &DACodecV2{},
		},
		{
			name: "Bernoulli active",
			config: &params.ChainConfig{
				LondonBlock:    big.NewInt(0),
				BernoulliBlock: big.NewInt(0),
			},
			blockNum:  big.NewInt(0),
			timestamp: 0,
			want:      &DACodecV1{},
		},
		{
			name: "London active",
			config: &params.ChainConfig{
				LondonBlock: big.NewInt(0),
			},
			blockNum:  big.NewInt(0),
			timestamp: 0,
			want:      &DACodecV0{},
		},
		{
			name:      "No upgrades",
			config:    &params.ChainConfig{},
			blockNum:  big.NewInt(0),
			timestamp: 0,
			want:      &DACodecV0{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CodecFromConfig(tt.config, tt.blockNum, tt.timestamp)
			assert.IsType(t, tt.want, got)
		})
	}
}
