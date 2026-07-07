package cmd

import (
	"encoding/json"
	"io"
)

// jsonNewEncoder returns an indented JSON encoder writing to w.
func jsonNewEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc
}
