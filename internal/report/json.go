package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON marshals reports as an indented JSON array to w.
func WriteJSON(w io.Writer, reports []PodReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(reports); err != nil {
		return fmt.Errorf("encoding reports as json: %w", err)
	}
	return nil
}
