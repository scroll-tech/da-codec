package encoding

type DACodecV9 struct {
	DACodecV8
}

func NewDACodecV9() *DACodecV9 {
	v := CodecV9
	return &DACodecV9{
		DACodecV8: DACodecV8{
			DACodecV7: DACodecV7{forcedVersion: &v},
		},
	}
}
