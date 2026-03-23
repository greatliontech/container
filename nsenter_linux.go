//go:build cgo

package container

// This import triggers CGO compilation of nsenter.c in the same package.
// The C constructor (__attribute__((constructor))) in nsenter.c runs
// before the Go runtime starts, handling namespace setup/joining.

import "C"

const builtinNsenter = true
