//go:build linux && arm64 && !musl
// +build linux,arm64,!musl

package zstd

/*
#cgo LDFLAGS: ${SRCDIR}/libencoder_legacy_linux_arm64.a ${SRCDIR}/libencoder_standard_linux_arm64.a
*/
import "C"
