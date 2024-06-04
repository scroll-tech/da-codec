//go:build !musl
// +build !musl

package codecv2

/*
#cgo LDFLAGS: ${SRCDIR}/libscroll_zstd_linux_arm64.a
*/
import "C"
