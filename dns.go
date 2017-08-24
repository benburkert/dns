package dns

import (
	"errors"
)

var (
	// ErrOversizedQuery is an error returned when attempting to send a query that
	// is longer than the maximum allowed number of bytes.
	ErrOversizedQuery = errors.New("oversized query")

	// ErrUnsupportedNetwork is returned when DialAddr is called with an
	// unknown network.
	ErrUnsupportedNetwork = errors.New("unsupported network")
)
