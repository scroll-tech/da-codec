//go:build !musl

package codecv2

/*
#cgo LDFLAGS: ${SRCDIR}/libscroll_zstd_linux_amd64.a
*/
import "C"
