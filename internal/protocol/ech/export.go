package ech

import (
	"encoding/pem"
	"io"
)

// SetPemEncodeHookForTest overrides pem.Encode during extractECHKeysPEM.
func SetPemEncodeHookForTest(fn func(io.Writer, *pem.Block) error) func() {
	prev := pemEncode
	if fn != nil {
		pemEncode = fn
	}
	return func() { pemEncode = prev }
}
