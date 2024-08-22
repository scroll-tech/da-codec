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

// CompressScrollBatchBytes compresses the given batch of bytes.
// The output buffer is allocated with an extra 128 bytes to accommodate metadata overhead or error message.
func CompressScrollBatchBytes(batchBytes []byte) ([]byte, error) {
	srcSize := C.uint64_t(len(batchBytes))
	outbufSize := C.uint64_t(len(batchBytes) + 128) // Allocate output buffer with extra 128 bytes
	outbuf := make([]byte, outbufSize)

	if err := C.compress_scroll_batch_bytes((*C.uchar)(unsafe.Pointer(&batchBytes[0])), srcSize,
		(*C.uchar)(unsafe.Pointer(&outbuf[0])), &outbufSize); err != nil {
		return nil, fmt.Errorf("failed to compress scroll batch bytes: %s", C.GoString(err))
	}

	return outbuf[:int(outbufSize)], nil
}
