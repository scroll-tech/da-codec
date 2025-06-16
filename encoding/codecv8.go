package encoding

type DACodecV8 struct {
	DACodecV7
}

func NewDACodecV8() *DACodecV8 {
	v := CodecV8
	return &DACodecV8{
		DACodecV7: DACodecV7{
			forcedVersion: &v,
		},
	}
}
