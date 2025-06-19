//go:build linux && amd64 && !musl
// +build linux,amd64,!musl

package zstd

/*
#cgo LDFLAGS: ${SRCDIR}/libencoder_legacy_linux_amd64.a ${SRCDIR}/libencoder_standard_linux_amd64.a
*/
import "C"
