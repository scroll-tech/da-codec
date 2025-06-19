//go:build darwin && arm64 && !musl
// +build darwin,arm64,!musl

package zstd

/*
#cgo LDFLAGS: ${SRCDIR}/libencoder_legacy_darwin_arm64.a ${SRCDIR}/libencoder_standard_darwin_arm64.a
*/
import "C"
