package dns

import "errors"

// ErrOversizedQuery is an error returned when attempting to send a query that
// is longer than the maximum allowed number of bytes.
var ErrOversizedQuery = errors.New("oversized query")
