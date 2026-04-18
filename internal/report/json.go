package report

import (
	"encoding/json"
	"io"
)

func RenderJSON(r *Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
