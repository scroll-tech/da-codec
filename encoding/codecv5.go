package encoding

type DACodecV5 struct {
	DACodecV4
}

func NewDACodecV5() *DACodecV5 {
	v := CodecV5
	return &DACodecV5{
		DACodecV4: DACodecV4{
			forcedVersion: &v,
		},
	}
}

// MaxNumChunksPerBatch returns the maximum number of chunks per batch.
func (d *DACodecV5) MaxNumChunksPerBatch() int {
	return 1
}
