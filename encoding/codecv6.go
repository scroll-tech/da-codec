package encoding

type DACodecV6 struct {
	DACodecV4
}

func NewDACodecV6() *DACodecV6 {
	v := CodecV6
	return &DACodecV6{
		DACodecV4: DACodecV4{
			forcedVersion: &v,
		},
	}
}
