package encoding

type DACodecV10 struct {
	DACodecV9
}

func NewDACodecV10() *DACodecV10 {
	v := CodecV10
	return &DACodecV10{
		DACodecV9: DACodecV9{
			DACodecV8: DACodecV8{
				DACodecV7: DACodecV7{forcedVersion: &v},
			},
		},
	}
}
