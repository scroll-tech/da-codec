package zstd

/*
#include <stdint.h>
char* compress_scroll_batch_bytes(uint8_t* src, uint64_t src_size, uint8_t* output_buf, uint64_t *output_buf_size);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const compressBufferOverhead = 128

// CompressScrollBatchBytes compresses the given batch of bytes using zstd compression.
// The output buffer is allocated with an extra compressBufferOverhead bytes to accommodate
// potential metadata overhead or error messages from the underlying C function.
func CompressScrollBatchBytes(batchBytes []byte) ([]byte, error) {
	if len(batchBytes) == 0 {
		return nil, fmt.Errorf("input batch is empty")
	}

	srcSize := C.uint64_t(len(batchBytes))
	outbufSize := C.uint64_t(len(batchBytes) + compressBufferOverhead)
	outbuf := make([]byte, outbufSize)

	if err := C.compress_scroll_batch_bytes((*C.uchar)(unsafe.Pointer(&batchBytes[0])), srcSize,
		(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outbufSize); err != nil {
		return nil, fmt.Errorf("failed to compress scroll batch bytes: %s", C.GoString(err))
	}

	return outbuf[:int(outbufSize)], nil
}
